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
using System.Linq;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using MindTouch.LambdaSharp.Tool.Model;
using MindTouch.LambdaSharp.Tool.Model.AST;
using Newtonsoft.Json;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using MindTouch.LambdaSharp.Tool.Internal;

namespace MindTouch.LambdaSharp.Tool {

    public class ModelParserException : Exception {

        //--- Constructors ---
        public ModelParserException(string message) : base(message) { }
    }

    public class ModelParser : AModelProcessor {

        //--- Constants ---
        private const string GITSHAFILE = "gitsha.txt";
        private const string PARAMETERSFILE = "parameters.json";
        private const string CLOUDFORMATION_ID_PATTERN = "[a-zA-Z][a-zA-Z0-9]*";
        private const string IMPORT_PATTERN = "^/?[a-zA-Z][a-zA-Z0-9]*(/[a-zA-Z][a-zA-Z0-9]*)*/?$";
        private const string SECRET_ALIAS_PATTERN = "[0-9a-zA-Z/_\\-]+";

        //--- Fields ---
        private Deployment _deployment;
        private ImportResolver _importer;
        private bool _noCompile;

        //--- Constructors ---
        public ModelParser(Settings settings) : base(settings) { }

        //--- Methods ---
        public Deployment Parse(YamlDotNet.Core.IParser yamlParser, bool noCompile) {
            _deployment = new Deployment {
                Settings = Settings
            };
            _noCompile = noCompile;
            _importer = new ImportResolver(Settings.SsmClient);

            // parse YAML file into deployment AST
            DeploymentNode appNode;
            try {
                appNode = new DeserializerBuilder()
                    .WithNamingConvention(new PascalCaseNamingConvention())
                    .Build()
                    .Deserialize<DeploymentNode>(yamlParser);
            } catch(Exception e) {
                AddError($"parse error: {e.Message}", e);
                return null;
            }

            // 'Version' attribute is obsolete
            if(appNode.Version != null) {
                AddError("the 'Version' attribute is no longer supported");
            }

            // convert deployment file
            try {
                return Convert(appNode);
            } catch(Exception e) {
                AddError($"internal error: {e.Message}", e);
                return null;
            }
        }

        private Deployment Convert(DeploymentNode deployment) {
            Validate(deployment.Name != null, "missing deployment name");

            // ensure collections are present
            if(deployment.Secrets == null) {
                deployment.Secrets = new List<string>();
            }
            if(deployment.Parameters == null) {
                deployment.Parameters = new List<ParameterNode>();
            }
            if(deployment.Functions == null) {
                deployment.Functions = new List<FunctionNode>();
            }

            // initialize deployment
            _deployment = new Deployment {
                Name = deployment.Name ?? "<BAD>",
                Settings = Settings,
                Description = deployment.Description
            };

            // convert secrets
            var secretIndex = 0;
            _deployment.Secrets = AtLocation("Secrets", () => deployment.Secrets
                .Select(secret => ConvertSecret(++secretIndex, secret))
                .Where(secret => secret != null)
                .ToList()
            , new List<string>());

            // check if we need to add a 'RollbarToken' parameter node
            if(
                (_deployment.Settings.RollbarCustomResourceTopicArn != null)
                && deployment.Functions.Any()
                && !deployment.Parameters.Any(param => param.Name == "RollbarToken")
            ) {
                deployment.Parameters.Add(new ParameterNode {
                    Name = "RollbarToken",
                    Description = "Rollbar project token",
                    Resource = new ResourceNode {
                        Type = "LambdaSharp::RollbarProject",
                        Allow = "None",
                        Properties = new Dictionary<string, object> {
                            ["ServiceToken"] = _deployment.Settings.RollbarCustomResourceTopicArn,
                            ["Project"] = _deployment.Name,
                            ["Tier"] = _deployment.Settings.Tier
                        }
                    }
                });
            }

            // resolve all imported parameters
            ImportValuesFromParameterStore(deployment);

            // convert parameters
            _deployment.Parameters = AtLocation("Parameters", () => ConvertParameters(deployment.Parameters), null) ?? new List<AParameter>();

            // create `parameters.json` serialization
            var functionParameters = new Dictionary<string, LambdaFunctionParameter>();
            foreach(var parameter in _deployment.Parameters) {
                AddFunctionParameter(parameter, functionParameters);
            }
            var functionParametersJson = JsonConvert.SerializeObject(functionParameters);

            // create functions
            _deployment.Functions = new List<Function>();
            if(deployment.Functions.Any()) {
                AtLocation("Functions", () => {

                    // check if a deployment bucket was specified
                    if(_deployment.Settings.DeploymentBucketName == null) {
                        AddError("deploying functions requires a deployment bucket");
                    }

                    // adde dead-letter queue permissions
                    if(_deployment.Settings.DeadLetterQueueUrl == null) {
                        AddError("deploying functions requires a dead letter queue ARN");
                    }
                });
                var functionIndex = 0;
                _deployment.Functions = AtLocation("Functions", () => deployment.Functions
                    .Select(function => ConvertFunction(++functionIndex, function, functionParametersJson))
                    .Where(function => function != null)
                    .ToList()
                , null) ?? new List<Function>();
            }
            return _deployment;
        }

        public string ConvertSecret(int index, object rawSecret) {
            return AtLocation($"[{index}]", () => {

                // resolve secret value
                var secret = rawSecret as string;
                if(string.IsNullOrEmpty(secret)) {
                    AddError($"secret has no value");
                    return null;
                }

                if(secret.Equals("aws/ssm", StringComparison.OrdinalIgnoreCase)) {
                    AddError($"cannot grant permission to decrypt with aws/ssm");
                    return null;
                }

                // check if secret is an ARN or KMS alias
                if(secret.StartsWith("arn:")) {

                    // validate secret arn
                    if(!Regex.IsMatch(secret, $"arn:aws:kms:{_deployment.Settings.AwsRegion}:{_deployment.Settings.AwsAccountId}:key/[a-fA-F0-9\\-]+")) {
                        AddError("secret key must be a valid ARN for the current region and account ID");
                        return null;
                    }

                    // decryption keys provided with their ARN can be added as is; no further steps required
                    return secret;
                }

                // validate regex for secret alias
                if(!Regex.IsMatch(secret, SECRET_ALIAS_PATTERN)) {
                    AddError("secret key must be a valid alias");
                    return null;
                }

                // assume key name is an alias and resolve it to its ARN
                try {
                    var response = _deployment.Settings.KmsClient.DescribeKeyAsync($"alias/{secret}").Result;
                    return response.KeyMetadata.Arn;
                } catch(Exception e) {
                    AddError($"failed to resolve key alias: {secret}", e);
                    return null;
                }
            }, null);
        }

        public IList<AParameter> ConvertParameters(
            IList<ParameterNode> parameters,
            string environmentPrefix = "STACK_",
            string resourcePrefix = ""
        ) {
            var resultList = new List<AParameter>();
            if((parameters == null) || !parameters.Any()) {
                return resultList;
            }

            // convert all parameters
            var index = 0;
            foreach(var parameter in parameters) {
                ++index;
                var parameterName = parameter.Name ?? $"[{index}]";
                AParameter result = null;
                AtLocation(parameterName, () => {
                    if(parameter.Name == null) {
                        AddError($"missing parameter name");
                        parameter.Name = "<BAD>";
                    } else if(!Regex.IsMatch(parameter.Name, CLOUDFORMATION_ID_PATTERN)) {
                        AddError($"parameter name is not valid");
                    }
                    if(parameter.Secret != null) {
                        ValidateNotBothStatements("Secret", "Import", parameter.Import == null);
                        ValidateNotBothStatements("Secret", "Parameters", parameter.Parameters == null);
                        ValidateNotBothStatements("Secret", "Value", parameter.Value == null);
                        ValidateNotBothStatements("Secret", "Values", parameter.Values == null);
                        ValidateNotBothStatements("Secret", "Package", parameter.Package == null);
                        ValidateNotBothStatements("Secret", "Resource", parameter.Resource == null);

                        // encrypted value
                        AtLocation("Secret", () => {
                            result = new SecretParameter {
                                Name = parameter.Name,
                                Description = parameter.Description,
                                Secret = parameter.Secret,
                                Export = parameter.Export,
                                EncryptionContext = null
                            };
                        });
                    } else if(parameter.Values != null) {
                        ValidateNotBothStatements("Values", "Import", parameter.Import == null);
                        ValidateNotBothStatements("Values", "Parameters", parameter.Parameters == null);
                        ValidateNotBothStatements("Values", "Value", parameter.Value == null);
                        ValidateNotBothStatements("Values", "Package", parameter.Package == null);

                        // list of values
                        AtLocation("Values", () => {
                            if(parameter.Resource != null) {
                                AtLocation("Resource", () => {
                                    for(var i = 1; i <= parameter.Values.Count; ++i) {

                                        // existing resource
                                        var resource = ConvertResource(parameter.Values[i - 1], parameter.Resource);
                                        resultList.Add(new ReferencedResourceParameter {
                                            Name = parameter.Name + i,
                                            Description = parameter.Description,
                                            Resource = resource
                                        });
                                    }
                                });
                            }

                            // convert a `StringList` into `String` parameter by concatenating the values, separated by a comma (`,`)
                            var value = string.Join(",", parameter.Values);
                            result = new StringParameter {
                                Name = parameter.Name,
                                Description = parameter.Description,
                                Value = value,
                                Export = parameter.Export
                            };
                        });
                    } else if(parameter.Parameters != null) {
                        ValidateNotBothStatements("Parameters", "Import", parameter.Import == null);
                        ValidateNotBothStatements("Parameters", "Value", parameter.Value == null);
                        ValidateNotBothStatements("Parameters", "Package", parameter.Package == null);
                        ValidateNotBothStatements("Parameters", "Resource", parameter.Resource == null);

                        // nested values
                        AtLocation("Parameters", () => {

                            // keep nested parameters only if they have values
                            var nestedParameters = ConvertParameters(
                                parameter.Parameters,
                                environmentPrefix + parameter.Name.ToUpperInvariant() + "_",
                                resourcePrefix + parameter.Name
                            );
                            if(nestedParameters.Any()) {
                                result = new CollectionParameter {
                                    Name = parameter.Name,
                                    Description = parameter.Description,
                                    Parameters = nestedParameters,
                                    Export = parameter.Export
                                };
                            }
                        });
                    } else if(parameter.Import != null) {
                        ValidateNotBothStatements("Import", "Value", parameter.Value == null);
                        ValidateNotBothStatements("Import", "Package", parameter.Package == null);

                        // imported value
                        AtLocation("Import", () => {
                            if(parameter.Import.EndsWith("/")) {

                                // TODO (2018-06-03, bjorg): convert multiple imported values into a parameter collection
                                AddError("importing parameter hierarchies are not yet supported");
                                if(parameter.Resource != null) {
                                    AddError($"cannot have 'Resource' for importing parameter hierarchies");
                                }
                            } else {
                                if(!_importer.TryGetValue(parameter.Import, out ResolvedImport value)) {
                                    AddError($"could not find import");
                                } else {

                                    // check the imported parameter store type
                                    switch(value.Type) {
                                    case "String":

                                        // imported string value could identify a resource
                                        if(parameter.Resource != null) {
                                            var resource = AtLocation("Resource", () => ConvertResource(value.Value, parameter.Resource), null);
                                            result = new ReferencedResourceParameter {
                                                Name = parameter.Name,
                                                Description = parameter.Description,
                                                Resource = resource
                                            };
                                        } else {
                                            result = new StringParameter {
                                                Name = parameter.Name,
                                                Description = parameter.Description,
                                                Value = value.Value
                                            };
                                        }
                                        break;
                                    case "StringList":
                                        Validate(parameter.Resource == null, "cannot have 'Resource' when importing a value of type 'StringList'");
                                        result = new StringParameter {
                                            Name = parameter.Name,
                                            Description = parameter.Description,
                                            Value = value.Value
                                        };
                                        break;
                                    case "SecureString":
                                        Validate(parameter.Resource == null, "cannot have 'Resource' when importing a value of type 'SecureString'");
                                        result = new SecretParameter {
                                            Name = parameter.Name,
                                            Description = parameter.Description,
                                            Secret = value.Value,
                                            EncryptionContext = new Dictionary<string, string> {
                                                ["PARAMETER_ARN"] = $"arn:aws:ssm:{_deployment.Settings.AwsRegion}:{_deployment.Settings.AwsAccountId}:parameter{parameter.Import}"
                                            }
                                        };
                                        break;
                                    default:
                                        AddError($"imported parameter has unsupported type '{value.Type}'");
                                        break;
                                    }
                                }
                            }

                        });
                    } else if(parameter.Package != null) {
                        ValidateNotBothStatements("Package", "Value", parameter.Value == null);
                        ValidateNotBothStatements("Package", "Resource", parameter.Resource == null);
                        if(parameter.Destination == null) {
                            AddError("missing 'Destination' attribute");
                        } else if(parameter.Destination.Bucket == null) {
                            AtLocation("Destination", () => {
                                AddError("missing 'Bucket' attribute");
                            });
                        } else {

                            // a package of one or more files
                            var files = new List<string>();
                            AtLocation("Package", () => {

                                // check if S3 sync topic arn exists
                                if(_deployment.Settings.S3PackageLoaderCustomResourceTopicArn == null) {
                                    AddError("parameter package requires S3PackageLoader custom resource handler to be deployed");
                                    return;
                                }

                                // check if package is nested
                                if(resourcePrefix != "") {
                                    AddError("parameter package cannot be nested");
                                    return;
                                }

                                // TODO (2018-07-25, bjorg): verify `Parameters` sections contains a valid S3 bucket reference
                                // var bucketParameterName = parameter.Destination.Bucket;
                                // var bucketParameter = _app.Parameters.FirstOrDefault(param => param.Name == bucketParameterName);
                                // if(bucketParameter == null) {
                                //     AddError($"could not find parameter for S3 bucket: '{bucketParameterName}'");
                                // } else if(!(bucketParameter is AResourceParameter resourceParameter)) {
                                //     AddError($"parameter for S3 bucket is not a resource: '{bucketParameterName}'");
                                // } else if(resourceParameter.Resource.Type != "AWS::S3::Bucket") {
                                //     AddError($"parameter for S3 bucket must be an S3 bucket resource: '{bucketParameterName}'");
                                // }
                                
                                // find all files that need to be part of the package
                                string folder;
                                string filePattern;
                                SearchOption searchOption;
                                if((parameter.Package.EndsWith("/", StringComparison.Ordinal) || Directory.Exists(parameter.Package))) {
                                    folder = Path.GetFullPath(parameter.Package);
                                    filePattern = "*";
                                    searchOption = SearchOption.AllDirectories;
                                } else {
                                    folder = Path.GetDirectoryName(parameter.Package);
                                    filePattern = Path.GetFileName(parameter.Package);
                                    searchOption = SearchOption.TopDirectoryOnly;
                                }
                                files.AddRange(Directory.GetFiles(folder, filePattern, searchOption));
                                files.Sort();

                                // compute MD5 hash for package
                                string package;
                                using(var md5 = MD5.Create()) {
                                    var bytes = new List<byte>();
                                    foreach(var file in files) {
                                        using(var stream = File.OpenRead(file)) {
                                            bytes.AddRange(md5.ComputeHash(stream));
                                        }
                                    }
                                    var hash = string.Concat(md5.ComputeHash(bytes.ToArray()).Select(x => x.ToString("X2")));
                                    package = $"{_deployment.Name}-{parameter.Name}-Package-{hash}.zip";
                                }

                                // create zip package
                                Console.WriteLine($"=> Building {parameter.Name} package");
                                if(File.Exists(package)) {
                                    try {
                                        File.Delete(package);
                                    } catch { }
                                }
                                using(var zipArchive = ZipFile.Open(package, ZipArchiveMode.Create)) {
                                    foreach(var file in files) {
                                        var filename = Path.GetRelativePath(folder, file);
                                        zipArchive.CreateEntryFromFile(file, filename);
                                    }
                                }

                                // package value
                                result = new PackageParameter {
                                    Name = parameter.Name,
                                    Description = parameter.Description,
                                    Package = package,
                                    Bucket = parameter.Destination.Bucket,
                                    PackageS3Key = $"{_deployment.Name}/{package}",
                                    Prefix = parameter.Destination.Prefix
                                };
                            });
                        }
                    } else if(parameter.Value != null) {
                        if(parameter.Resource != null) {
                            AtLocation("Resource", () => {

                                // existing resource
                                var resource = ConvertResource(parameter.Value, parameter.Resource);
                                result = new ReferencedResourceParameter {
                                    Name = parameter.Name,
                                    Description = parameter.Description,
                                    Resource = resource
                                };
                            });
                        } else {

                            // plaintext value
                            result = new StringParameter {
                                Name = parameter.Name,
                                Description = parameter.Description,
                                Value = parameter.Value
                            };
                        }
                    } else {

                        // managed resource
                        AtLocation("Resource", () => {
                            result = new CloudFormationResourceParameter {
                                Name = resourcePrefix + parameter.Name,
                                Description = parameter.Description,
                                Resource = ConvertResource(null, parameter.Resource)
                            };
                        });
                    }
                });
                if(result != null) {
                    result.Export = parameter.Export;
                    resultList.Add(result);
                }
            }
            return resultList;

            // local functions
            void ValidateNotBothStatements(string attribute1, string attribute2, bool condition) {
                if(!condition) {
                    AddError($"attributes '{attribute1}' and '{attribute2}' are not allowed at the same time");
                }
            }
        }

        public Resource ConvertResource(string resourceArn, ResourceNode resource) {

            // parse resource type
            var resourceType = "<BAD>";
            if(resource.Type == null) {
                if(resourceArn != null) {
                    resource.Type = "AWS";
                } else {
                    AddError("missing Type field");
                }
            } else {
                resourceType = AtLocation("Type", () => {
                    if(resource.Type.StartsWith("Custom::")) {
                        if(resource.ServiceTokenImport is string serviceTokenImport) {
                            if(!_importer.TryGetValue(serviceTokenImport, out string importedValue)) {
                                AddError("unable to find custom resource handler topic");
                                return "<BAD>";
                            }

                            // add resolved `ServiceToken` to custom resource
                            if(resource.Properties == null) {
                                resource.Properties = new Dictionary<string, object>();
                            }
                            resource.Properties["ServiceToken"] = importedValue;
                        }
                    } else if(!_deployment.Settings.ResourceMapping.IsResourceTypeSupported(resource.Type)) {
                        AddError($"unsupported resource type: {resource.Type}");
                        return "<BAD>";
                    }
                    return resource.Type;
                }, "<BAD>");
            }

            // parse resource allowed operations
            var allowList = new List<string>();
            if((resource.Type != null) && (resource.Allow != null)) {
                AtLocation("Allow", () => {
                    if(resource.Allow is string inlineValue) {

                        // inline values can be separated by `,`
                        allowList.AddRange(inlineValue.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries));
                    } else if(resource.Allow is IList<object> allowed) {
                        allowList = allowed.Cast<string>().ToList();
                    } else {
                        AddError("invalid allow value");
                        return;
                    }

                    // resolve shorthands and de-duplicated statements
                    var allowSet = new HashSet<string>();
                    foreach(var allowStatement in allowList) {
                        if(allowStatement == "None") {

                            // nothing to do
                        } else if(allowStatement.Contains(':')) {

                            // AWS permission statements always contain a `:` (e.g `ssm:GetParameter`)
                            allowSet.Add(allowStatement);
                        } else if(_deployment.Settings.ResourceMapping.TryResolveAllowShorthand(resourceType, allowStatement, out IList<string> allowedList)) {
                            foreach(var allowed in allowedList) {
                                allowSet.Add(allowed);
                            }
                        } else {
                            AddError($"could not find IAM mapping for short-hand '{allowStatement}' on AWS type '{resource.Type}'");
                        }
                    }
                    allowList = allowSet.OrderBy(text => text).ToList();
                });
            }

            // ensure the local resource name is an ARN or wildcard
            if(resourceArn != null) {
                if(!resourceArn.StartsWith("arn:") && (resourceArn != "*")) {
                    AddError("resource name must be in ARN or wildcard format");
                }
                if(resource.Properties != null) {
                    AddError($"referenced resource '{resourceArn}' cannot set properties");
                }
            }
            return new Resource {
                Type = resourceType,
                ResourceArn = resourceArn,
                Allow = allowList,
                Properties = resource.Properties
            };
        }

        public Function ConvertFunction(int index, FunctionNode function, string functionParametersJson) {
            return AtLocation(function.Name ?? $"[{index}]", () => {
                Validate(function.Name != null, "missing Name field");
                Validate(function.Memory != null, "missing Memory field");
                Validate(int.TryParse(function.Memory, out _), "invalid Memory value");
                Validate(function.Timeout != null, "missing Name field");
                Validate(int.TryParse(function.Timeout, out _), "invalid Timeout value");

                // initialize VPC configuration if provided
                FunctionVpc vpc = null;
                if(function.VPC is string vpcName) {
                    AtLocation("VPC", () => {
                        if(!_importer.TryGetValue(vpcName, out IEnumerable<ResolvedImport> imports)) {
                            AddError($"could not find VPC information for {vpcName}");
                            return;
                        }
                        var subnetIdsText = imports.FirstOrDefault(import => import.Key == vpcName + "SubnetIds");
                        var subnetIds = new string[0];
                        var securityGroupIdsText = imports.FirstOrDefault(import => import.Key == vpcName + "SecurityGroupsIds");
                        var securityGroupIds = new string[0];
                        if(subnetIdsText == null) {
                            AddError($"{vpcName}SubnetIds is missing");
                        } else if(subnetIdsText.Type != "StringList") {
                            AddError($"{vpcName}SubnetIds has type '{subnetIdsText.Type}', expected 'StringList'");
                        } else {
                            subnetIds = subnetIdsText.Value.Split(',', StringSplitOptions.RemoveEmptyEntries);
                            if(!subnetIds.Any()) {
                                AddError($"{vpcName}SubnetIds is empty'");
                            }
                        }
                        if(securityGroupIdsText == null) {
                            AddError($"{vpcName}SecurityGroupsIds is missing");
                        } else if(securityGroupIdsText.Type != "StringList") {
                            AddError($"{vpcName}SecurityGroupsIds has type '{subnetIdsText.Type}', expected 'StringList'");
                        } else {
                            securityGroupIds = securityGroupIdsText.Value.Split(',', StringSplitOptions.RemoveEmptyEntries);
                            if(!securityGroupIds.Any()) {
                                AddError($"{vpcName}SecurityGroupsIds is empty'");
                            }
                        }
                        if(!subnetIds.Any() || !securityGroupIds.Any()) {
                            return;
                        }
                        vpc = new FunctionVpc {
                            SubnetIds = subnetIds,
                            SecurityGroupIds = securityGroupIds
                        };
                    });
                }

                // compile function project
                var handler = function.Handler;
                var runtime = function.Runtime;
                var zipFinalPackage = AtLocation("Project", () => {
                    var projectName = function.Project ?? $"{_deployment.Name}.{function.Name}";
                    var project = Path.Combine(_deployment.Settings.WorkingDirectory, projectName, projectName + ".csproj");
                    string targetFramework;

                    // check if csproj file exists in project folder
                    if(!File.Exists(project)) {
                        AddError($"could not find function project: {project}");
                        return null;
                    } else {

                        // check if the handler/runtime were provided or if they need to be extracted from the project file
                        var csproj = XDocument.Load(project);
                        var mainPropertyGroup = csproj.Element("Project")?.Element("PropertyGroup");

                        // make sure the .csproj file contains the lambda tooling
                        var hasAwsLambdaTools = csproj.Element("Project")
                            ?.Elements("ItemGroup")
                            .Any(el => (string)el.Element("DotNetCliToolReference")?.Attribute("Include") == "Amazon.Lambda.Tools") ?? false;
                        if(!hasAwsLambdaTools) {
                            AddError($"the project is missing the AWS lambda tool defintion; make sure that {project} includes <DotNetCliToolReference Include=\"Amazon.Lambda.Tools\"/>");
                            return null;
                        }

                        // check if we need to read the project file <RootNamespace> element to determine the handler name
                        if(handler == null) {
                            var rootNamespace = mainPropertyGroup?.Element("RootNamespace")?.Value;
                            if(rootNamespace != null) {
                                handler = $"{projectName}::{rootNamespace}.Function::FunctionHandlerAsync";
                            } else {
                                AddError("could not auto-determine handler; either add Function field or <RootNamespace> to project file");
                                handler = "<BAD>";
                            }
                        }

                        // check if we need to parse the <TargetFramework> element to determine the lambda runtime
                        targetFramework = mainPropertyGroup?.Element("TargetFramework").Value;
                        if(runtime == null) {
                            switch(targetFramework) {
                            case "netcoreapp1.0":
                                runtime = "dotnetcore1.0";
                                break;
                            case "netcoreapp2.0":
                                runtime = "dotnetcore2.0";
                                break;
                            case "netcoreapp2.1":
                                runtime = "dotnetcore2.1";
                                break;
                            default:
                                AddError("could not auto-determine handler; add Runtime field");
                                break;
                            }
                        }
                    }
                    if(_noCompile) {
                        return $"{projectName}-NOCOMPILE.zip";
                    }

                    // dotnet tools have to be run from the project folder; otherwise specialized tooling is not picked up from the .csproj file
                    var projectDirectory = Path.Combine(_deployment.Settings.WorkingDirectory, projectName);
                    foreach(var file in Directory.GetFiles(_deployment.Settings.WorkingDirectory, $"{projectName}-*.zip")) {
                        try {
                            File.Delete(file);
                        } catch { }
                    }
                    Console.WriteLine($"Building function {projectName} [{targetFramework}]");

                    // restore project dependencies
                    Console.WriteLine("=> Restoring project dependencies");
                    if(!DotNetRestore(projectDirectory)) {
                        AddError("`dotnet restore` command failed");
                        return null;
                    }

                    // compile project
                    Console.WriteLine("=> Building AWS Lambda package");
                    if(!DotNetLambdaPackage(targetFramework, projectName, projectDirectory)) {
                        AddError("`dotnet lambda package` command failed");
                        return null;
                    }

                    // check if the project zip file was created
                    var zipOriginalPackage = Path.Combine(_deployment.Settings.WorkingDirectory, projectName, projectName + ".zip");
                    if(!File.Exists(zipOriginalPackage)) {
                        AddError($"could not find project package: {zipOriginalPackage}");
                        return null;
                    }

                    // decompress project zip into temporary folder so we can add the `parameters.json` and `GITSHAFILE` files
                    string package;
                    var tempDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                    try {

                        // extract existing package into temp folder
                        Console.WriteLine("=> Decompressing AWS Lambda package");
                        if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                            ZipFile.ExtractToDirectory(zipOriginalPackage, tempDirectory);
                            File.Delete(zipOriginalPackage);
                        } else {
                            Directory.CreateDirectory(tempDirectory);
                            if(!UnzipWithTool(zipOriginalPackage, tempDirectory)) {
                                AddError("`unzip` command failed");
                                return null;
                            }
                        }

                        // add `parameters.json` file to temp folder
                        Console.WriteLine("=> Adding settings file 'parameters.json'");
                        File.WriteAllText(Path.Combine(tempDirectory, PARAMETERSFILE), functionParametersJson);

                        // add `gitsha.txt` if GitSha is supplied
                        if(_deployment.Settings.GitSha != null) {
                            File.WriteAllText(Path.Combine(tempDirectory, GITSHAFILE), _deployment.Settings.GitSha);
                        }

                        // compress temp folder into new package
                        var zipTempPackage = Path.GetTempFileName() + ".zip";
                        if(File.Exists(zipTempPackage)) {
                            File.Delete(zipTempPackage);
                        }

                        // compute MD5 hash
                        var files = new List<string>();
                        using(var md5 = MD5.Create()) {
                            var bytes = new List<byte>();
                            files.AddRange(Directory.GetFiles(tempDirectory, "*", SearchOption.AllDirectories));
                            files.Sort();
                            foreach(var file in files) {
                                var filename = Path.GetFileName(file);

                                // don't include the `gitsha.txt` since it changes with every build
                                if(filename != GITSHAFILE) {
                                    using(var stream = File.OpenRead(file)) {
                                        bytes.AddRange(md5.ComputeHash(stream));
                                    }
                                }
                            }
                            var hash = string.Concat(md5.ComputeHash(bytes.ToArray()).Select(x => x.ToString("X2")));
                            package = Path.Combine(_deployment.Settings.WorkingDirectory, $"{projectName}-{hash}.zip");
                        }

                        // compress folder contents
                        Console.WriteLine("=> Finalizing AWS Lambda package");
                        if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                            using(var zipArchive = ZipFile.Open(zipTempPackage, ZipArchiveMode.Create)) {
                                foreach(var file in files) {

                                    // TODO (2018-07-24, bjorg): I doubt this works correctly for files in subfolders
                                    var filename = Path.GetFileName(file);
                                    zipArchive.CreateEntryFromFile(file, filename);
                                }
                            }
                        } else {
                            if(!ZipWithTool(zipTempPackage, tempDirectory)) {
                                AddError("`zip` command failed");
                                return null;
                            }
                        }
                        File.Move(zipTempPackage, package);
                    } finally {
                        if(Directory.Exists(tempDirectory)) {
                            try {
                                Directory.Delete(tempDirectory, recursive: true);
                            } catch {
                                Console.WriteLine($"WARNING: clean-up failed for temporary directory: {tempDirectory}");
                            }
                        }
                    }
                    return package;
                }, null);

                // create function
                var eventIndex = 0;
                return new Function {
                    Name = function.Name ,
                    Description = function.Description,
                    Sources = AtLocation("Sources", () => function.Sources?.Select(source => ConvertFunctionSource(++eventIndex, source)).Where(evt => evt != null).ToList(), null) ?? new List<AFunctionSource>(),
                    Package = zipFinalPackage,
                    PackageS3Key = $"{_deployment.Name}/{Path.GetFileName(zipFinalPackage)}",
                    Handler = handler,
                    Runtime = runtime,
                    Memory = function.Memory,
                    Timeout = function.Timeout,
                    ReservedConcurrency = function.ReservedConcurrency,
                    VPC = vpc,
                    Environment = function.Environment ?? new Dictionary<string, string>()
                };
            }, null);
        }

        public AFunctionSource ConvertFunctionSource(int index, FunctionSourceNode source) {
            return AtLocation<AFunctionSource>($"{index}", () => {
                if(source.Topic != null) {
                    ValidateNotBothStatements("Topic", "Schedule", source.Schedule == null);
                    ValidateNotBothStatements("Topic", "Api", source.Api == null);
                    ValidateNotBothStatements("Topic", "SlackCommand", source.SlackCommand == null);
                    ValidateNotBothStatements("Topic", "S3", source.S3 == null);
                    ValidateNotBothStatements("Topic", "Events", source.Events == null);
                    ValidateNotBothStatements("Topic", "Prefix", source.Prefix == null);
                    ValidateNotBothStatements("Topic", "Suffix", source.Suffix == null);
                    ValidateNotBothStatements("Topic", "Sqs", source.Sqs == null);
                    ValidateNotBothStatements("Topic", "Alexa", source.Alexa == null);
                    return new TopicSource {
                        TopicName = AtLocation("Topic", () => {

                            // verify `Parameters` sections contains a valid topic reference
                            var topicName = source.Topic;
                            var parameter = _deployment.Parameters.FirstOrDefault(param => param.Name == topicName);
                            if(parameter == null) {
                                AddError($"could not find parameter for SNS topic: '{topicName}'");
                            } else if(!(parameter is AResourceParameter resourceParameter)) {
                                AddError($"parameter for SNS topic is not a resource: '{topicName}'");
                            } else if(resourceParameter.Resource.Type != "AWS::SNS::Topic") {
                                AddError($"parameter for SNS topic must be an SNS topic resource: '{topicName}'");
                            }
                            return topicName;
                        }, "<BAD>")
                    };
                }
                if(source.Schedule != null) {
                    ValidateNotBothStatements("Schedule", "Api", source.Api == null);
                    ValidateNotBothStatements("Schedule", "SlackCommand", source.SlackCommand == null);
                    ValidateNotBothStatements("Schedule", "S3", source.S3 == null);
                    ValidateNotBothStatements("Schedule", "Events", source.Events == null);
                    ValidateNotBothStatements("Schedule", "Prefix", source.Prefix == null);
                    ValidateNotBothStatements("Schedule", "Suffix", source.Suffix == null);
                    ValidateNotBothStatements("Schedule", "Sqs", source.Sqs == null);
                    ValidateNotBothStatements("Schedule", "Alexa", source.Alexa == null);
                    return AtLocation("Schedule", () => {

                        // TODO (2018-06-27, bjorg): missing expression validation
                        return new ScheduleSource {
                            Expression = source.Schedule,
                            Name = source.Name  
                        };
                    }, null);
                }
                if(source.Api != null) {
                    ValidateNotBothStatements("Api", "S3", source.S3 == null);
                    ValidateNotBothStatements("Api", "Events", source.Events == null);
                    ValidateNotBothStatements("Api", "Prefix", source.Prefix == null);
                    ValidateNotBothStatements("Api", "Suffix", source.Suffix == null);
                    ValidateNotBothStatements("Api", "Sqs", source.Sqs == null);
                    ValidateNotBothStatements("Api", "Alexa", source.Alexa == null);
                    return AtLocation("Api", () => {

                        // extract http method from route
                        var api = source.Api.Trim();
                        var pathSeparatorIndex = api.IndexOfAny(new[] { ':', ' ' });
                        if(pathSeparatorIndex < 0) {
                            AddError("invalid api format");
                            return new ApiGatewaySource {
                                Method = "ANY",
                                Path = new string[0],
                                Integration = ApiGatewaySourceIntegration.RequestResponse
                            };
                        }
                        var method = api.Substring(0, pathSeparatorIndex).ToUpperInvariant();
                        if(method == "*") {
                            method = "ANY";
                        }
                        var path = api.Substring(pathSeparatorIndex + 1).TrimStart().Split('/', StringSplitOptions.RemoveEmptyEntries);

                        // parse integration into a valid enum
                        var integration = AtLocation("Integration", () => Enum.Parse<ApiGatewaySourceIntegration>(source.Integration ?? "RequestResponse", ignoreCase: true), ApiGatewaySourceIntegration.Unsupported);
                        return new ApiGatewaySource {
                            Method = method,
                            Path = path,
                            Integration = integration
                        };
                    }, null);
                }
                if(source.SlackCommand != null) {
                    ValidateNotBothStatements("SlackCommand", "S3", source.S3 == null);
                    ValidateNotBothStatements("SlackCommand", "Events", source.Events == null);
                    ValidateNotBothStatements("SlackCommand", "Prefix", source.Prefix == null);
                    ValidateNotBothStatements("SlackCommand", "Suffix", source.Suffix == null);
                    ValidateNotBothStatements("SlackCommand", "Sqs", source.Sqs == null);
                    ValidateNotBothStatements("SlackCommand", "Alexa", source.Alexa == null);
                    return AtLocation("SlackCommand", () => {

                        // parse integration into a valid enum
                        return new ApiGatewaySource {
                            Method = "POST",
                            Path = source.SlackCommand.Split('/', StringSplitOptions.RemoveEmptyEntries),
                            Integration = ApiGatewaySourceIntegration.SlackCommand
                        };
                    }, null);
                }
                if(source.S3 != null) {
                    ValidateNotBothStatements("S3", "Sqs", source.Sqs == null);
                    ValidateNotBothStatements("S3", "Alexa", source.Alexa == null);
                    return AtLocation("S3", () => {

                        // TODO (2018-06-27, bjorg): missing events, prefix, suffix validation
                        var s3 = new S3Source {
                            Bucket = source.S3,
                            Events = source.Events ?? new List<string> {

                                // default S3 events to listen to
                                "s3:ObjectCreated:*"
                            },
                            Prefix = source.Prefix,
                            Suffix = source.Suffix
                        };

                        // verify `Parameters` sections contains a valid bucket reference
                        var parameter = _deployment.Parameters.FirstOrDefault(param => param.Name == s3.Bucket);
                        if(parameter == null) {
                            AddError($"could not find parameter for S3 bucket: '{s3.Bucket}'");
                        } else if(!(parameter is AResourceParameter resourceParameter)) {
                            AddError($"parameter for S3 bucket is not a resource: '{s3.Bucket}'");
                        } else if(resourceParameter.Resource.Type != "AWS::S3::Bucket") {
                            AddError($"parameter for S3 bucket must be an S3 bucket resource: '{s3.Bucket}'");
                        }
                        return s3;
                    }, null);
                }
                if(source.Sqs != null) {
                    ValidateNotBothStatements("Sqs", "Events", source.Events == null);
                    ValidateNotBothStatements("Sqs", "Prefix", source.Prefix == null);
                    ValidateNotBothStatements("Sqs", "Suffix", source.Suffix == null);
                    ValidateNotBothStatements("Sqs", "Alexa", source.Alexa == null);
                    return AtLocation("Sqs", () => {
                        var sqs = new SqsSource {
                            Queue = source.Sqs,
                            BatchSize = source.BatchSize ?? 10
                        };
                        AtLocation("BatchSize", () => {
                            if((sqs.BatchSize < 1) || (sqs.BatchSize > 10)) {
                                AddError($"invalid BatchSize value: {sqs.BatchSize}");
                            }
                        });

                        // verify `Parameters` sections contains a valid queue reference
                        var parameter = _deployment.Parameters.FirstOrDefault(param => param.Name == sqs.Queue);
                        if(parameter == null) {
                            AddError($"could not find parameter for SQS queue: '{sqs.Queue}'");
                        } else if(!(parameter is AResourceParameter resourceParameter)) {
                            AddError($"parameter for SQS queue is not a resource: '{sqs.Queue}'");
                        } else if(resourceParameter.Resource.Type != "AWS::SQS::Queue") {
                            AddError($"parameter for SQS queue must be an SQS queue resource: '{sqs.Queue}'");
                        }
                        return sqs;
                    }, null);
                }
                if(source.Alexa != null) {
                    return AtLocation("Alexa", () => {
                        var alexaSkillId = (string.IsNullOrWhiteSpace(source.Alexa) || source.Alexa == "*") 
                            ? null 
                            : source.Alexa;
                        return new AlexaSource {
                            EventSourceToken = alexaSkillId
                        };
                    }, null);
                }
                AddError("empty event");
                return null;
            }, null);
            throw new ModelParserException("invalid function event");

            // local functions
            void ValidateNotBothStatements(string attribute1, string attribute2, bool condition) {
                if(!condition) {
                    AddError($"attributes '{attribute1}' and '{attribute2}' are not allowed at the same time");
                }
            }
        }

        private void AddFunctionParameter(
            AParameter parameter,
            IDictionary<string, LambdaFunctionParameter> functionParameters
        ) {
            switch(parameter) {
            case SecretParameter secretParameter:
                functionParameters.Add(parameter.Name, new LambdaFunctionParameter {
                    Type = LambdaFunctionParameterType.Secret,
                    Value = secretParameter.Secret,
                    EncryptionContext = secretParameter.EncryptionContext
                });
                break;
            case CollectionParameter collectionParameter: {
                    var nestedFunctionParameters = new Dictionary<string, LambdaFunctionParameter>();
                    if(collectionParameter.Parameters != null) {
                        foreach(var nestedResource in collectionParameter.Parameters) {
                            AddFunctionParameter(
                                nestedResource,
                                nestedFunctionParameters
                            );
                        }
                    }
                    if(nestedFunctionParameters.Any()) {
                        functionParameters.Add(parameter.Name, new LambdaFunctionParameter {
                            Type = LambdaFunctionParameterType.Collection,
                            Value = nestedFunctionParameters
                        });
                    }
                }
                break;
            case StringParameter stringParameter:
                functionParameters.Add(parameter.Name, new LambdaFunctionParameter {
                    Type = LambdaFunctionParameterType.Text,
                    Value = stringParameter.Value
                });
                break;
            case PackageParameter packageParameter:
                functionParameters.Add(parameter.Name, new LambdaFunctionParameter {
                    Type = LambdaFunctionParameterType.Stack,
                    Value = null
                });
                break;
            case ReferencedResourceParameter referenceResourceParameter:
                functionParameters.Add(parameter.Name, new LambdaFunctionParameter {
                    Type = LambdaFunctionParameterType.Text,
                    Value = referenceResourceParameter.Resource.ResourceArn
                });
                break;
            case CloudFormationResourceParameter cloudFormationResourceParameter:
                functionParameters.Add(parameter.Name, new LambdaFunctionParameter {
                    Type = LambdaFunctionParameterType.Stack,
                    Value = null
                });
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(parameter), parameter, "unknown parameter type");
            }
        }

        private void ImportValuesFromParameterStore(DeploymentNode deployment) {

            // find all parameters with an `Import` field
            AtLocation("Parameters", () => FindAllParameterImports());
            AtLocation("Functions", () => FindAllFunctionImports());

            // resolve all imported values
            _importer.BatchResolveImports();

            // check if any imports were not found
            foreach(var missing in _importer.MissingImports) {
                AddError($"import parameter '{missing}' not found");
            }
            return;

            // local functions
            void FindAllParameterImports(IEnumerable<ParameterNode> @params = null) {
                var paramIndex = 0;
                foreach(var param in @params ?? deployment.Parameters) {
                    ++paramIndex;
                    var paramName = param.Name ?? $"#{paramIndex}";
                    if(param.Import != null) {
                        AtLocation("Import", () => {
                            if(!Regex.IsMatch(param.Import, IMPORT_PATTERN)) {
                                AddError("import value is invalid");
                                return;
                            }

                            // check if import requires a deployment tier prefix
                            if(!param.Import.StartsWith("/")) {
                                param.Import = $"/{_deployment.Settings.Tier}/" + param.Import;
                            }
                            _importer.Add(param.Import);
                        });
                    }

                    // check if we need to import a custom resource handler topic
                    var resourceType = param?.Resource?.Type;
                    if((resourceType != null) && !resourceType.StartsWith("AWS::")) {
                        AtLocation(paramName, () => {
                            AtLocation("Resource", () => {
                                AtLocation("Type", () => {

                                    // confirm the custom resource has a `ServiceToken` specified or imports one
                                    if(resourceType.StartsWith("Custom::") || (resourceType == "AWS::CloudFormation::CustomResource")) {
                                        if(param.Resource.ServiceTokenImport != null) {
                                            param.Resource.ServiceTokenImport = param.Resource.ServiceTokenImport;
                                            _importer.Add(param.Resource.ServiceTokenImport);
                                        } else {
                                            AtLocation("Properties", () => {
                                                if(!(param.Resource.Properties?.ContainsKey("ServiceToken") ?? false)) {
                                                    AddError("missing ServiceToken in custom resource properties");
                                                }
                                            });
                                        }
                                        return;
                                    }

                                    // parse resource name as `{DEPLOYMENT}::{TYPE}` pattern to import the custom resource topic name
                                    var customResourceHandlerAndType = resourceType.Split("::");
                                    if(customResourceHandlerAndType.Length != 2) {
                                        AddError("custom resource type must have format {DEPLOYMENT}::{TYPE}");
                                        return;
                                    }
                                    if(!Regex.IsMatch(customResourceHandlerAndType[0], CLOUDFORMATION_ID_PATTERN)) {
                                        AddError($"custom resource prefix must be alphanumeric: {customResourceHandlerAndType[0]}");
                                        return;
                                    }
                                    if(!Regex.IsMatch(customResourceHandlerAndType[1], CLOUDFORMATION_ID_PATTERN)) {
                                        AddError($"custom resource suffix must be alphanumeric: {customResourceHandlerAndType[1]}");
                                        return;
                                    }
                                    param.Resource.Type = "Custom::" + param.Resource.Type.Replace("::", "");

                                    // check if custom resource needs a service token to be retrieved
                                    if(!(param.Resource.Properties?.ContainsKey("ServiceToken") ?? false)) {
                                        var serviceTokenImport = $"/{_deployment.Settings.Tier}"
                                            + $"/{customResourceHandlerAndType[0]}"
                                            + $"/{customResourceHandlerAndType[1]}CustomResourceTopic";
                                        param.Resource.ServiceTokenImport = serviceTokenImport;
                                        _importer.Add(serviceTokenImport);    
                                    }
                                });
                            });
                        });
                    }

                    // check if we need to recurse into nested parameters
                    if(param.Parameters != null) {
                        AtLocation(paramName, () => {
                            FindAllParameterImports(param.Parameters);
                        });
                    }
                }
            }

            void FindAllFunctionImports() {
                foreach(var function in deployment.Functions.Where(function => function.VPC != null)) {
                    AtLocation(function.Name, () => {
                        var vpc = function.VPC;
                        if(!string.IsNullOrEmpty(vpc)) {
                            if(!vpc.StartsWith("/")) {
                                vpc = $"/{_deployment.Settings.Tier}/VPC/{vpc}/";
                            }
                            _importer.Add(vpc);
                        }
                        function.VPC = vpc;
                    });
                }

            }
        }

        private void Validate(bool condition, string message) {
            if(!condition) {
                AddError(message);
            }
        }

        private bool DotNetRestore(string projectDirectory) {
            var dotNetExe = ProcessLauncher.DotNetExe;
            if(string.IsNullOrEmpty(dotNetExe)) {
                AddError("failed to find the \"dotnet\" executable in path.");
                return false;
            }
            return ProcessLauncher.Execute(
                dotNetExe,
                new[] { "restore" },
                projectDirectory,
                _deployment.Settings.VerboseLevel >= VerboseLevel.Detailed
            );
        }

        private bool DotNetLambdaPackage(string targetFramework, string projectName, string projectDirectory) {
            var dotNetExe = ProcessLauncher.DotNetExe;
            if(string.IsNullOrEmpty(dotNetExe)) {
                AddError("failed to find the \"dotnet\" executable in path.");
                return false;
            }
            return ProcessLauncher.Execute(
                dotNetExe,
                new[] { "lambda", "package", "-c", "Release", "-f", targetFramework, "-o", projectName + ".zip" },
                projectDirectory,
                _deployment.Settings.VerboseLevel >= VerboseLevel.Detailed
            );
        }

        private bool ZipWithTool(string zipArchivePath, string zipFolder) {
            var zipTool = ProcessLauncher.ZipExe;
            if(string.IsNullOrEmpty(zipTool)) {
                AddError("failed to find the \"zip\" utility program in path. This program is required to maintain Linux file permissions in the zip archive.");
                return false;
            }
            return ProcessLauncher.Execute(
                zipTool,
                new[] { "-r", zipArchivePath, "." },
                zipFolder,
                _deployment.Settings.VerboseLevel >= VerboseLevel.Detailed
            );
        }

        private bool UnzipWithTool(string zipArchivePath, string unzipFolder) {
            var unzipTool = ProcessLauncher.UnzipExe;
            if(unzipTool == null) {
                AddError("failed to find the \"unzip\" utility program in path. This program is required to maintain Linux file permissions in the zip archive.");
                return false;
            }
            return ProcessLauncher.Execute(
                unzipTool,
                new[] { zipArchivePath, "-d", unzipFolder },
                Directory.GetCurrentDirectory(),
                _deployment.Settings.VerboseLevel >= VerboseLevel.Detailed
            );
        }
    }
}