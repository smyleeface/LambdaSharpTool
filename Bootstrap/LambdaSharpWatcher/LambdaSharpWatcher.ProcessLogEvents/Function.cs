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
using System.Text;
using System.Threading.Tasks;
using Amazon.Lambda.Core;
using Amazon.Lambda.KinesisEvents;
using MindTouch.LambdaSharp;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace MindTouch.LambdaSharpWatcher.ProcessLogEvents {

    public class LogEventsMessage {

        //--- Properties ---
        public string Owner { get; set; }
        public string LogGroup { get; set; }
        public string LogStream { get; set; }
        public string MessageType { get; set; }
        public List<string> SubscriptionFilters { get; set; }
        public List<LogEventEntry> LogEvents { get; set; }
    }

    public class LogEventEntry {

        //--- Properties ---
        public string Id { get; set; }
        public string Timestamp { get; set; }
        public string Message { get; set; }
    }

    public class Function : ALambdaFunction<KinesisEvent, string> {

        //--- Methods ---
        public override Task InitializeAsync(LambdaConfig config)
            => Task.CompletedTask;

        public override async Task<string> ProcessMessageAsync(KinesisEvent evt, ILambdaContext context) {
            LogInfo($"# Kinesis Records = {evt.Records.Count}");
            for(var i = 0; i < evt.Records.Count; ++i) {
                var record = evt.Records[i];
                LogInfo($"Record #{i}");
                LogInfo($"AwsRegion = {record.AwsRegion}");
                LogInfo($"EventId = {record.EventId}");
                LogInfo($"EventName = {record.EventName}");
                LogInfo($"EventSource = {record.EventSource}");
                LogInfo($"EventSourceARN = {record.EventSourceARN}");
                LogInfo($"EventVersion = {record.EventVersion}");
                LogInfo($"InvokeIdentityArn = {record.InvokeIdentityArn}");
                LogInfo($"ApproximateArrivalTimestamp = {record.Kinesis.ApproximateArrivalTimestamp}");
                LogInfo($"Kinesis.Data.Length = {record.Kinesis.Data.Length}");
                LogInfo($"Kinesis.KinesisSchemaVersion = {record.Kinesis.KinesisSchemaVersion}");
                LogInfo($"KinesisPartitionKey = {record.Kinesis.PartitionKey}");
                LogInfo($"KinesisSequenceNumber = {record.Kinesis.SequenceNumber}");

                LogEventsMessage events;
                using(var decompressedStream = new MemoryStream()) {
                    using(var gzip = new GZipStream(record.Kinesis.Data, CompressionMode.Decompress)) {
                        gzip.CopyTo(decompressedStream);
                        decompressedStream.Position = 0;
                    }
                    events = DeserializeJson<LogEventsMessage>(decompressedStream);
                }

                if(!events.LogGroup.Contains("LambdaSharpWatcher")) {
                    LogInfo($"LogEvents.Owner = {events.Owner}");
                    if(!string.IsNullOrEmpty(events.LogGroup)) {
                        LogInfo($"LogEvents.LogGroup = {events.LogGroup}");
                    }
                    if(!string.IsNullOrEmpty(events.LogStream)) {
                        LogInfo($"LogEvents.LogStream = {events.LogStream}");
                    }
                    LogInfo($"LogEvents.MessageType = {events.MessageType}");
                    for(var j = 0; j < events.SubscriptionFilters.Count; ++j) {
                        LogInfo($"LogEvents.SubscriptionFilters[{j}] = {events.SubscriptionFilters[j]}");
                    }
                    for(var j = 0; j < events.LogEvents.Count; ++j) {
                        if(!string.IsNullOrEmpty(events.LogEvents[j].Id)) {
                            LogInfo($"LogEvents.LogEvents[{j}].Id = {events.LogEvents[j].Id}");
                        }
                        if(!string.IsNullOrEmpty(events.LogEvents[j].Timestamp)) {
                            LogInfo($"LogEvents.LogEvents[{j}].Timestamp = {events.LogEvents[j].Timestamp}");
                        }
                        LogInfo($"LogEvents.LogEvents[{j}].Message = {events.LogEvents[j].Message}");
                    }
                }
            }
            return "Ok";
        }
    }
}