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
using McMaster.Extensions.CommandLineUtils;

namespace MindTouch.LambdaSharp.Tool.Cli {

    public class CliPublishCommand : ACliCommand {

        //--- Class Methods ---
        public void Register(CommandLineApplication app) {
            app.Command("publish", cmd => {
                cmd.HelpOption();
                cmd.Description = "Publish LambdaSharp module";
                var dryRunOption = cmd.Option("--dryrun:<LEVEL>", "(optional) Generate output assets without deploying (0=everything, 1=cloudformation)", CommandOptionType.SingleOrNoValue);
                var outputCloudFormationFilePathOption = cmd.Option("--output <FILE>", "(optional) Name of generated CloudFormation template file (default: bin/cloudformation.json)", CommandOptionType.SingleValue);
                var initSettingsCallback = CreateSettingsInitializer(cmd);
                cmd.OnExecute(async () => {
                    Console.WriteLine($"{app.FullName} - {cmd.Description}");

                    // read settings and validate them
                    var settingsCollection = await initSettingsCallback();
                    if(settingsCollection == null) {
                        return;
                    }
                    foreach(var settings in settingsCollection) {
                        if(!settings.IsLocalModule) {
                            AddError("cannot publish a remote module");
                            return;
                        }
                        if(!File.Exists(settings.ModuleSource)) {
                            AddError($"could not find '{settings.ModuleSource}'");
                        }
                    }
                    if(ErrorCount > 0) {
                        return;
                    }
                    DryRunLevel? dryRun = null;
                    if(dryRunOption.HasValue()) {
                        DryRunLevel value;
                        if(!TryParseEnumOption(dryRunOption, DryRunLevel.Everything, out value)) {

                            // NOTE (2018-08-04, bjorg): no need to add an error message since it's already added by `TryParseEnumOption`
                            return;
                        }
                        dryRun = value;
                    }
                    Console.WriteLine($"Publishing module to '{settingsCollection.First().DeploymentBucketName}'");
                    foreach(var settings in settingsCollection) {
                        if(!await Publish(
                            settings,
                            dryRun,
                            outputCloudFormationFilePathOption.Value() ?? Path.Combine(settings.OutputDirectory, "cloudformation.json")
                        )) {
                            break;
                        }
                    }
                });
            });
        }

        private async Task<bool> Publish(
            Settings settings,
            DryRunLevel? dryRun,
            string outputCloudFormationFilePath
        ) {
            var stopwatch = Stopwatch.StartNew();

            // check if a deployment bucket was specified
            if(dryRun != DryRunLevel.CloudFormation) {
                if(settings.DeploymentBucketName == null) {
                    AddError("deploying functions requires a deployment bucket", new LambdaSharpDeploymentTierSetupException(settings.Tier));
                    return false;
                }
            }

            // read input file
            Console.WriteLine();
            Console.WriteLine($"Processing module: {settings.ModuleSource}");
            var source = await File.ReadAllTextAsync(settings.ModuleSource);

            // parse yaml module file
            var module = new ModelParser(settings).Process(source);
            if(ErrorCount > 0) {
                return false;
            }

            // reset settings when the 'LambdaSharp` module is being deployed
            if(module.Name == "LambdaSharp") {
                settings.Reset();
            }

            // validate module
            new ModelValidation(settings).Process(module);
            if(ErrorCount > 0) {
                return false;
            }

            // package all functions
            new ModelFunctionPackager(settings).Process(module, skipCompile: dryRun == DryRunLevel.CloudFormation);
            if(ErrorCount > 0) {
                return false;
            }

            // package all files
            new ModelFilesPackager(settings).Process(module);
            if(ErrorCount > 0) {
                return false;
            }

            // upload assets
            await new ModelUploader(settings).ProcessAsync(
                module,
                settings.DeploymentBucketName,
                skipUpload: dryRun == DryRunLevel.CloudFormation,
                publish: true,

                // TODO (2018-08-22, bjorg): add command line option to control force update
                forceUpdate: true
            );
            if(ErrorCount > 0) {
                return false;
            }
            Console.WriteLine($"Done (duration: {stopwatch.Elapsed:c})");
            return true;
        }
    }
}