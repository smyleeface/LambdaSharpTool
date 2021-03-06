﻿/*
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
using MindTouch.Rollbar.Data;

namespace MindTouch.Rollbar.Builders {

    public class TraceChainBuilder : ITraceChainBuilder {

        //--- Fields ---
        private readonly ITraceBuilder _traceBuilder;

        //--- Constructors ---
        public TraceChainBuilder(ITraceBuilder traceBuilder) {
            if(traceBuilder == null) {
                throw new ArgumentNullException("traceBuilder");
            }
            _traceBuilder = traceBuilder;
        }

        //--- Methods ---
        public IEnumerable<Trace> CreateFromException(Exception exception, string description) {
            var exceptions = exception.FlattenHierarchy();
            var traces = new List<Trace>();
            traces.AddRange(Build(exceptions.First(), description));
            traces.AddRange(exceptions.Skip(1).SelectMany(ex => Build(ex, null)));
            traces.Reverse();
            return traces;
        }

        private IEnumerable<Trace> Build(Exception exception, string description) {
            var result = new List<Trace>(2);
            result.Add(_traceBuilder.CreateFromException(exception, description));
            return result;
        }
    }
}
