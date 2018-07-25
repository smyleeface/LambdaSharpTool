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
using System.IO;
using System.IO.Compression;
using System.Threading.Tasks;
using Amazon.Lambda.Core;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;
using MindTouch.LambdaSharp;
using MindTouch.LambdaSharp.CustomResource;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace MindTouch.LambdaSharpS3PackageLoader.ResourceHandler {

    public class RequestProperties {

        //--- Properties ---
        public string DestinationBucketName { get; set; }
        public string DestinationKeyPrefix { get; set; }
        public string SourceBucketName { get; set; }
        public string SourcePackageKey { get; set; }
    }

    public class ResponseProperties {

        //--- Properties ---
        public string Result { get; set; }
    }

    public class Function : ALambdaCustomResourceFunction<RequestProperties, ResponseProperties> {

        //--- Fields ---
        private IAmazonS3 _s3Client;
        private TransferUtility _transferUtility;

        //--- Methods ---
        public override Task InitializeAsync(LambdaConfig config) {
            _s3Client = new AmazonS3Client();
            _transferUtility = new TransferUtility(_s3Client);
            return Task.CompletedTask;
        }

        protected override Task<Response<ResponseProperties>> HandleCreateResourceAsync(Request<RequestProperties> request)
            => UploadFiles(request.ResourceProperties);

        protected override Task<Response<ResponseProperties>> HandleDeleteResourceAsync(Request<RequestProperties> request)
            => DeleteFiles(request.ResourceProperties);

        protected override async Task<Response<ResponseProperties>> HandleUpdateResourceAsync(Request<RequestProperties> request) {
            await DeleteFiles(request.OldResourceProperties);
            return await UploadFiles(request.ResourceProperties);
        }

        private async Task<Response<ResponseProperties>> UploadFiles(RequestProperties properties) {
            await ProcessZipFileEntriesAsync(properties.SourceBucketName, properties.SourcePackageKey, async entry => {
                using(var stream = entry.Open()) {
                    var memoryStream = new MemoryStream();
                    await stream.CopyToAsync(memoryStream);
                    await _transferUtility.UploadAsync(
                        memoryStream, 
                        properties.DestinationBucketName, 
                        Path.Combine(properties.DestinationKeyPrefix, entry.FullName)
                    );
                }
            });
            return new Response<ResponseProperties> {
                PhysicalResourceId = $"s3package:{properties.DestinationBucketName}:{properties.DestinationKeyPrefix}/{properties.DestinationKeyPrefix}",
                Properties = new ResponseProperties {
                    Result = $"s3://{properties.DestinationBucketName}/{properties.DestinationKeyPrefix}"
                }
            };
        }

        private async Task<Response<ResponseProperties>> DeleteFiles(RequestProperties properties) {
            await ProcessZipFileEntriesAsync(properties.SourceBucketName, properties.SourcePackageKey, async entry => {
                await _s3Client.DeleteObjectAsync(new DeleteObjectRequest {
                    BucketName = properties.DestinationBucketName,
                    Key = Path.Combine(properties.DestinationKeyPrefix, entry.FullName)
                });
            });
            return new Response<ResponseProperties>();
        }

        private async Task ProcessZipFileEntriesAsync(string bucketName, string key, Func<ZipArchiveEntry, Task> callbackAsync) {
            var tmpFilename = Path.GetTempFileName() + ".zip";
            await _transferUtility.DownloadAsync(new TransferUtilityDownloadRequest {
                BucketName = bucketName,
                Key = key,
                FilePath = tmpFilename
            });
            try {
                using(var zip = ZipFile.Open(tmpFilename, ZipArchiveMode.Read)) {
                    foreach(var entry in zip.Entries) {
                        await callbackAsync(entry);
                    }
                }
            } finally {
                try {
                    File.Delete(tmpFilename);
                } catch { }
            }
        }
    }
}