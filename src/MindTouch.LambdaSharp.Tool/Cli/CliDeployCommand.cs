/*
 * MindTouch λ#
 * Copyright (C) 2006-2018 MindTouch, Inc.
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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Humidifier.Json;
using McMaster.Extensions.CommandLineUtils;
using MindTouch.LambdaSharp.Tool.Internal;

namespace MindTouch.LambdaSharp.Tool.Cli {

    public class CliDeployCommand : ACliCommand {

        //--- Class Methods ---
        public void Register(CommandLineApplication app) {
            app.Command("deploy", cmd => {
                cmd.HelpOption();
                cmd.Description = "Deploy LambdaSharp app";
                var inputFileOption = cmd.Option("--input <FILE>", "(optional) YAML app deployment file (default: Deploy.yml)", CommandOptionType.SingleValue);
                var dryRunOption = cmd.Option("--dryrun:<LEVEL>", "(optional) Generate output assets without deploying (0=everything, 1=cloudformation)", CommandOptionType.SingleOrNoValue);
                var outputFilename = cmd.Option("--output <FILE>", "(optional) Name of generated CloudFormation template file (default: cloudformation.json)", CommandOptionType.SingleValue);
                var allowDataLossOption = cmd.Option("--allow-data-loss", "(optional) Allow CloudFormation resource update operations that could lead to data loss", CommandOptionType.NoValue);
                var initSettingsCallback = CreateSettingsInitializer(cmd);
                cmd.OnExecute(async () => {
                    Console.WriteLine($"{app.FullName} - {cmd.Description}");
                    var settings = await initSettingsCallback();
                    if(settings == null) {
                        return;
                    }
                    DryRunLevel? dryRun = null;
                    if(dryRunOption.HasValue()) {
                        DryRunLevel value;
                        if(!TryParseEnumOption(dryRunOption, DryRunLevel.Everything, out value)) {
                            return;
                        }
                        dryRun = value;
                    }
                    await Deploy(
                        settings,
                        inputFileOption.Value() ?? "Deploy.yml",
                        dryRun,
                        outputFilename.Value() ?? "cloudformation.json",
                        allowDataLossOption.HasValue()
                    );
                });
            });
        }

        private async Task Deploy(
            Settings settings,
            string inputFile,
            DryRunLevel? dryRun,
            string outputFilename,
            bool allowDataLoos
        ) {
            if(settings == null) {
                return;
            }
            var stopwatch = Stopwatch.StartNew();

            // read input file
            settings.DeploymentFileName = Path.GetFullPath(inputFile);
            settings.WorkingDirectory = Path.GetDirectoryName(settings.DeploymentFileName);
            if(!File.Exists(settings.DeploymentFileName)) {
                AddError($"could not find '{settings.DeploymentFileName}'");
                return;
            }
            Console.WriteLine($"Loading '{inputFile}'");
            var source = await File.ReadAllTextAsync(settings.DeploymentFileName);

            // preprocess file
            Console.WriteLine("Pre-processing");
            var parser = new ModelPreprocessor(settings).Preprocess(source);
            if(_errors.Any()) {
                return;
            }

            // parse yaml app file
            Console.WriteLine("Analyzing");
            var app = new ModelParser(settings).Parse(parser, dryRun == DryRunLevel.CloudFormation);
            if(_errors.Any()) {
                return;
            }

            // generate cloudformation template
            var generator = new ModelGenerator();
            var stack = generator.Generate(app);
            if(_errors.Any()) {
                return;
            }

            // serialize stack to disk
            var outputPath = Path.Combine(settings.WorkingDirectory, outputFilename);
            var template = new JsonStackSerializer().Serialize(stack);
            File.WriteAllText(outputPath, template);
            if(dryRun == null) {
                await new StackUpdater().Deploy(app, template, allowDataLoos);

                // remove dryrun file if it exists
                if(File.Exists(outputPath)) {
                    try {
                        File.Delete(outputPath);
                    } catch { }
                }
            }
            Console.WriteLine($"Done (duration: {stopwatch.Elapsed:c})");
        }
    }
}
