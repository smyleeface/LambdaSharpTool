/*
 * MindTouch λ#
 * Copyright (C) 2018 MindTouch, Inc.
 * www.mindtouch.com  oss@mindtouch.com
 *
 * For community documentation and downloads visit mindtouch.com;
 * please review the licensing section.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Lambda.Core;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using Amazon.SQS;
using MindTouch.LambdaSharp.ConfigSource;
using MindTouch.Rollbar;
using Newtonsoft.Json;

namespace MindTouch.LambdaSharp {

    public abstract class ALambdaFunction {

        //--- Constants ---
        private const int MAX_SNS_SIZE = 262144;

        //--- Class Fields ---
        private static readonly Stopwatch Stopwatch = Stopwatch.StartNew();
        private static int Invocations;

        //--- Fields ---
        private readonly Func<DateTime> _now;
        private readonly DateTime _started;
        private readonly IAmazonKeyManagementService _kmsClient;
        private readonly IAmazonSimpleNotificationService _snsClient;
        private readonly IAmazonSQS _sqsClient;
        private readonly ILambdaConfigSource _envSource;
        private IRollbarClient _rollbarClient;
        private string _deadLetterQueueUrl;
        private string _errorTopic;
        private bool _initialized;
        private LambdaConfig _appConfig;
        private string _deployment;
        private string _appName;
        private string _stackName;

        //--- Constructors ---
        protected ALambdaFunction() : this(LambdaFunctionConfiguration.Instance) { }

        protected ALambdaFunction(LambdaFunctionConfiguration configuration) {
            _now = configuration.UtcNow ?? (() => DateTime.UtcNow);
            _kmsClient = configuration.KmsClient ?? throw new ArgumentNullException(nameof(configuration.KmsClient));
            _snsClient = configuration.SnsClient ?? throw new ArgumentNullException(nameof(configuration.SnsClient));
            _sqsClient = configuration.SqsClient ?? throw new ArgumentNullException(nameof(configuration.SqsClient));
            _envSource = configuration.EnvironmentSource ?? throw new ArgumentNullException(nameof(configuration.EnvironmentSource));
            _started = UtcNow;
        }

        //--- Properties ---
        protected DateTime UtcNow => _now();
        protected DateTime Started => _started;

        //--- Abstract Methods ---
        public abstract Task InitializeAsync(LambdaConfig config);
        public abstract Task<object> ProcessMessageStreamAsync(Stream stream, ILambdaContext context);

        //--- Methods ---
        public async Task<object> FunctionHandlerAsync(Stream stream, ILambdaContext context) {
            try {

                // function startup
                Stopwatch.Restart();
                ++Invocations;
                var now = UtcNow;
                LogInfo($"function age: {now - Started:c}");
                LogInfo($"function invocation counter: {Invocations:N0}");

                // check if function needs to be initialized
                if(!_initialized) {
                    try {
                        LogInfo("start function initialization");
                        await InitializeAsync(_envSource, context);
                        await InitializeAsync(_appConfig);
                        LogInfo("end function initialization");
                        _initialized = true;
                    } catch(Exception e) {
                        LogFatal(e, "failed during function initialization");
                        throw;
                    }
                }

                // process message stream
                object result;
                try {
                    result = await ProcessMessageStreamAsync(stream, context);
                } catch(ALambdaRetriableException e) {
                    LogErrorAsWarning(e, "failed during message stream processing");
                    throw;
                } catch(Exception e) {
                    LogError(e, "failed during message stream processing");
                    throw;
                }
                return result;
            } finally {
                LogInfo("invocation completed");
            }
        }

        protected virtual async Task InitializeAsync(ILambdaConfigSource envSource, ILambdaContext context) {

            // read bootstrap configuration from environment
            _deployment = envSource.Read("DEPLOYMENT");
            _appName = envSource.Read("APPNAME");
            _stackName = envSource.Read("STACKNAME");
            _deadLetterQueueUrl = envSource.Read("DEADLETTERQUEUE");
            _errorTopic = envSource.Read("ERRORTOPIC");
            var framework = envSource.Read("LAMBDARUNTIME");
            LogInfo($"DEPLOYMENT = {_deployment}");
            LogInfo($"APPNAME = {_appName}");
            LogInfo($"STACKNAME = {_stackName}");
            LogInfo($"DEADLETTERQUEUE = {_deadLetterQueueUrl ?? "NONE"}");
            LogInfo($"ERRORTOPIC = {_errorTopic ?? "NONE"}");
            LogInfo($"ROLLBARERRORTOPIC = {_errorTopic ?? "NONE"}");

            // read optional git-sha file
            var gitsha = File.Exists("gitsha.txt") ? File.ReadAllText("gitsha.txt") : null;
            LogInfo($"GITSHA = {gitsha ?? "NONE"}");

            // read app configuration values from parameters file
            var parameters = await ParseParameters("/", File.ReadAllText("parameters.json"));

            // use app config where environment variables take precedence over those found in the parameter store
            _appConfig = new LambdaConfig(new LambdaMultiSource(new[] {
                envSource,
                new LambdaDictionarySource("", parameters)
            }));

            // initialize rollbar
            var rollbarAccessToken = _appConfig.ReadText("RollbarToken", defaultValue: null);
            if(rollbarAccessToken != null) {
                const string proxy = "";
                const string platform = "lambda";
                _rollbarClient = RollbarClient.Create(new RollbarConfiguration(
                    rollbarAccessToken,
                    proxy,
                    _deployment,
                    platform,
                    framework,
                    gitsha
                ));
                LogInfo("Rollbar = ENABLED");
            } else {
                LogInfo("Rollbar = DISABLED");
            }

            // local functions
            async Task<Dictionary<string, string>> ParseParameters(string parameterPrefix, string json) {
                var functionParameters = JsonConvert.DeserializeObject<Dictionary<string, LambdaFunctionParameter>>(json);
                var flatten = new Dictionary<string, string>();
                await Flatten(functionParameters, parameterPrefix, "STACK_", flatten);
                return flatten;

                // local functions
                async Task Flatten(Dictionary<string, LambdaFunctionParameter> source, string prefix, string envPrefix, Dictionary<string, string> target) {
                    foreach(var kv in source) {
                        var value = kv.Value.Value;
                        switch(kv.Value.Type) {
                        case LambdaFunctionParameterType.Collection:
                            await Flatten((Dictionary<string, LambdaFunctionParameter>)value, prefix + kv.Key + "/", envPrefix + kv.Key.ToUpperInvariant() + "_", target);
                            break;
                        case LambdaFunctionParameterType.Secret: {
                                var secret = (string)value;
                                var plaintextStream = (await _kmsClient.DecryptAsync(new DecryptRequest {
                                    CiphertextBlob = new MemoryStream(Convert.FromBase64String(secret)),
                                    EncryptionContext = kv.Value.EncryptionContext
                                })).Plaintext;
                                target.Add(prefix + kv.Key, Encoding.UTF8.GetString(plaintextStream.ToArray()));
                                break;
                            }
                        case LambdaFunctionParameterType.Stack:
                            target.Add(prefix + kv.Key, envSource.Read(envPrefix + kv.Key.ToUpperInvariant()));
                            break;
                        case LambdaFunctionParameterType.Text:
                            target.Add(prefix + kv.Key, (string)value);
                            break;
                        default:
                            throw new NotSupportedException($"unsupported parameter type: '{kv.Value.Type.ToString()}'");
                        }
                    }
                }
            }
        }

        protected virtual async Task RecordFailedMessageAsync(LambdaLogLevel level, string body, Exception exception) {
            if(!string.IsNullOrEmpty(_deadLetterQueueUrl)) {
                await _sqsClient.SendMessageAsync(_deadLetterQueueUrl, body);
            } else {
                LogWarn("dead letter queue not configured");
                throw new LambdaFunctionException("dead letter queue not configured", exception);
            }
        }

        #region *** Logging ***
        protected void LogInfo(string format, params object[] args)
            => Log(LambdaLogLevel.INFO, exception: null, format: format, args: args);

        protected void LogWarn(string format, params object[] args)
            => Log(LambdaLogLevel.WARNING, exception: null, format: format, args: args);

        protected void LogError(Exception exception, string format, params object[] args)
            => Log(LambdaLogLevel.ERROR, exception, format, args);

        protected void LogErrorAsInfo(Exception exception, string format, params object[] args)
            => Log(LambdaLogLevel.INFO, exception, format, args);

        protected void LogErrorAsWarning(Exception exception, string format, params object[] args)
            => Log(LambdaLogLevel.WARNING, exception, format, args);

        protected void LogFatal(Exception exception, string format, params object[] args)
            => Log(LambdaLogLevel.FATAL, exception, format, args);

        private void Log(LambdaLogLevel level, string message, string extra)
            => LambdaLogger.Log($"*** {level.ToString().ToUpperInvariant()}: {message} [{Stopwatch.Elapsed:c}]\n{extra}");

        private void Log(LambdaLogLevel level, Exception exception, string format, params object[] args) {
            string message = RollbarClient.FormatMessage(format, args);
            Log(level, $"{message}", exception?.ToString());
            if(level >= LambdaLogLevel.WARNING) {
                if(_rollbarClient != null) {
                    try {
                        Log(LambdaLogLevel.INFO, $"rollbar sending data", extra: null);
                        var result = _rollbarClient.SendAsync(level.ToString(), exception, format, args).GetAwaiter().GetResult();
                        if(!result.IsSuccess) {
                            Log(LambdaLogLevel.ERROR, $"Rollbar payload request failed. {result.Message}. UUID: {result.UUID}", extra: null);
                        }
                    } catch(Exception e) {
                        Log(LambdaLogLevel.ERROR, $"rollbar client exception", e.ToString());
                    }
                } else if(_errorTopic != null) {

                    // send exception to error-topic
                    _snsClient.PublishAsync(new PublishRequest {
                        TopicArn = _errorTopic,
                        Message = _rollbarClient.CreatePayload(MAX_SNS_SIZE, level.ToString(), exception, format, args),
                        MessageAttributes = new Dictionary<string, MessageAttributeValue> {
                            ["Deployment"] = new MessageAttributeValue {
                                StringValue = _deployment
                            },
                            ["AppName"] = new MessageAttributeValue {
                                StringValue = _appName
                            }
                        }
                    }).GetAwaiter().GetResult();
                }
            }
        }
        #endregion
    }
}
