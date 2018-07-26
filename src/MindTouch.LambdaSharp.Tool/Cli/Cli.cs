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
using System.Collections.Generic;

namespace MindTouch.LambdaSharp.Tool.Cli {


    public class CliBase {

        //--- Class Fields ---
        protected static IList<(string Message, Exception Exception)> _errors = new List<(string Message, Exception Exception)>();
        protected static VerboseLevel _verboseLevel = VerboseLevel.Normal;
        protected static Version _version = typeof(Program).Assembly.GetName().Version;

        //--- Class Methods ---
        protected static void AddError(string message, Exception exception = null)
            => _errors.Add((Message: message, Exception: exception));

        protected static void AddError(Exception exception)
            => AddError(exception.Message, exception);
    }
}
