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
using System.Text.RegularExpressions;
using Humidifier;
using MindTouch.LambdaSharp.Tool.Model;

namespace MindTouch.LambdaSharp.Tool {

    public class ModelReferenceResolver : AModelProcessor {

        //--- Constants ---
        private const string SUBVARIABLE_PATTERN = @"\$\{(?!\!)[^\}]+\}";

        //--- Constructors ---
        public ModelReferenceResolver(Settings settings) : base(settings) { }

        //--- Methods ---
        public void Resolve(Module module) {
            var freeParameters = new Dictionary<string, AParameter>();
            var boundParameters = new Dictionary<string, AParameter>();

            // resolve all inter-parameter references
            AtLocation("Parameters", () => {
                DiscoverParameters(module.Parameters);

                // resolve parameter variables via substitution
                while(ResolveParameters(boundParameters.ToList()));

                // report circular dependencies, if any
                ReportUnresolved(module.Parameters);
                if(Settings.HasErrors) {
                    return;
                }
            });

            // resolve references in resource properties
            AtLocation("Variables", () => {
                foreach(var parameter in module.Parameters
                    .Where(p => p.Scope == ParameterScope.Module)
                    .OfType<AResourceParameter>()
                    .Where(p => p.Resource?.Properties != null)
                ) {
                    AtLocation(parameter.Name, () => {
                        AtLocation("Resource", () => {
                            AtLocation("Properties", () => {
                                parameter.Resource.Properties = new Dictionary<string, object>(
                                    parameter.Resource.Properties.Select(kv => new KeyValuePair<string, object>(kv.Key, Substitute(kv.Value)))
                                );
                            });
                        });
                    });
                }
            });

            // resolve references in resource properties
            AtLocation("Parameters", () => {
                foreach(var parameter in module.Parameters
                    .Where(p => p.Scope == ParameterScope.Function)
                    .OfType<AResourceParameter>()
                    .Where(p => p.Resource?.Properties != null)
                ) {
                    AtLocation(parameter.Name, () => {
                        AtLocation("Resource", () => {
                            AtLocation("Properties", () => {
                                parameter.Resource.Properties = new Dictionary<string, object>(
                                    parameter.Resource.Properties.Select(kv => new KeyValuePair<string, object>(kv.Key, Substitute(kv.Value)))
                                );
                            });
                        });
                    });
                }
            });

            // resolve references in output values
            AtLocation("Outputs", () => {
                foreach(var output in module.Outputs) {
                    switch(output) {
                    case StackOutput stackOutput:
                        AtLocation(stackOutput.Name, () => {
                            stackOutput.Value = Substitute(stackOutput.Value);
                        });
                        break;
                    case ExportOutput exportOutput:
                        AtLocation(exportOutput.ExportName, () => {
                            exportOutput.Value = Substitute(exportOutput.Value);
                        });
                        break;
                    case CustomResourceHandlerOutput customResourceHandlerOutput:

                        // nothing to do
                        break;
                    default:
                        throw new InvalidOperationException($"cannot resolve references for this type: {output?.GetType()}");
                    }
                }
            });

            // resolve references in functions
            AtLocation("Functions", () => {
                foreach(var function in module.Functions) {
                    AtLocation(function.Name, () => {
                        function.Environment = new Dictionary<string, object>(
                            function.Environment.Select(kv => new KeyValuePair<string, object>(kv.Key, Substitute(kv.Value)))
                        );
                        if(function.VPC != null) {
                            function.VPC.SecurityGroupIds = Substitute(function.VPC.SecurityGroupIds);
                            function.VPC.SubnetIds = Substitute(function.VPC.SubnetIds);
                        }
                    });
                }
            });

            // local functions
            void DiscoverParameters(IEnumerable<AParameter> parameters) {
                if(parameters == null) {
                    return;
                }
                foreach(var parameter in parameters) {
                    switch(parameter) {
                    case ValueParameter valueParameter:
                        if(valueParameter.Reference is string) {
                            freeParameters[parameter.ResourceName] = parameter;
                        } else {
                            boundParameters[parameter.ResourceName] = parameter;
                        }
                        break;
                    case ValueListParameter listParameter:
                        if(listParameter.Values.All(value => value is string)) {
                            freeParameters[parameter.ResourceName] = parameter;
                        } else {
                            boundParameters[parameter.ResourceName] = parameter;
                        }
                        break;
                    case ReferencedResourceParameter referencedParameter:
                        if(referencedParameter.Resource.ResourceReferences.All(value => value is string)) {
                            freeParameters[parameter.ResourceName] = parameter;
                        } else {
                            boundParameters[parameter.ResourceName] = parameter;
                        }
                        break;
                    case CloudFormationResourceParameter cloudFormationResourceParameter:
                        if(cloudFormationResourceParameter.Resource.Properties?.Any() != true) {
                            freeParameters[parameter.ResourceName] = parameter;
                        } else {
                            boundParameters[parameter.ResourceName] = parameter;
                        }
                        break;
                    case AInputParameter inputParameter:
                        freeParameters[parameter.ResourceName] = parameter;
                        break;
                    default:

                        // TODO (2018-10-03, bjorg): what about `SecretParameter` and `PackageParameter`?
                        break;
                    }
                    DiscoverParameters(parameter.Parameters);
                }
            }

            bool ResolveParameters(IEnumerable<KeyValuePair<string, AParameter>> parameters) {
                if(parameters == null) {
                    return false;
                }
                var progress = false;
                foreach(var kv in parameters) {

                    // NOTE (2018-10-04, bjorg): each iteration, we loop over a bound variable;
                    //  in the iteration, we attempt to substitute all references with free variables;
                    //  if we do, the variable can be added to the pool of free variables;
                    //  if we iterate over all bound variables without making progress, then we must have
                    //  a circular dependency and we stop.

                    var parameter = kv.Value;
                    AtLocation(parameter.Name, () => {
                        var doesNotContainBoundParameters = true;
                        switch(parameter) {
                        case ValueParameter _:
                        case ValueListParameter _:
                        case ReferencedResourceParameter _:
                            parameter.Reference = Substitute(parameter.Reference, CheckBoundParameters);
                            break;
                        case CloudFormationResourceParameter cloudFormationResourceParameter:
                            cloudFormationResourceParameter.Resource.Properties = (IDictionary<string, object>)Substitute(cloudFormationResourceParameter.Resource.Properties, CheckBoundParameters);
                            break;
                        default:
                            throw new InvalidOperationException($"cannot resolve references for this type: {parameter?.GetType()}");
                        }
                        if(doesNotContainBoundParameters) {

                            // capture that progress towards resolving all bound variables has been made;
                            // if ever an iteration does not produces progress, we need to stop; otherwise
                            // we will loop forever
                            progress = true;

                            // promote bound variable to free variable
                            freeParameters[kv.Key] = parameter;
                            boundParameters.Remove(kv.Key);
                        }

                        // local functions
                        void CheckBoundParameters(string missingName)
                            => doesNotContainBoundParameters = doesNotContainBoundParameters && !boundParameters.ContainsKey(missingName.Replace("::", ""));
                    });
                }
                return progress;
            }

            void ReportUnresolved(IEnumerable<AParameter> parameters) {
                if(parameters == null) {
                    return;
                }
                foreach(var parameter in parameters) {
                    AtLocation(parameter.Name, () => {
                        switch(parameter) {
                        case ValueParameter valueParameter:
                            Substitute(valueParameter.Reference, missingName => {
                                if(boundParameters.ContainsKey(missingName)) {
                                    AddError($"circular !Ref dependency on '{missingName}'");
                                } else {
                                    AddError($"could not find !Ref dependency '{missingName}'");
                                }
                            });
                            break;
                        case ValueListParameter valueListParameter:
                            foreach(var item in valueListParameter.Values) {
                                Substitute(item, missingName => {
                                    if(boundParameters.ContainsKey(missingName)) {
                                        AddError($"circular !Ref dependency on '{missingName}'");
                                    } else {
                                        AddError($"could not find !Ref dependency '{missingName}'");
                                    }
                                });
                            }
                            break;
                        case ReferencedResourceParameter referencedResourceParameter:
                            foreach(var item in referencedResourceParameter.Resource.ResourceReferences) {
                                Substitute(item, missingName => {
                                    if(boundParameters.ContainsKey(missingName)) {
                                        AddError($"circular !Ref dependency on '{missingName}'");
                                    } else {
                                        AddError($"could not find !Ref dependency '{missingName}'");
                                    }
                                });
                            }
                            break;
                        case CloudFormationResourceParameter _:
                        case PackageParameter _:
                        case SecretParameter _:
                        case AInputParameter _:

                            // nothing to do
                            break;
                        default:
                            throw new InvalidOperationException($"cannot check unresolved references for this type: {parameter?.GetType()}");
                        }
                        ReportUnresolved(parameter.Parameters);
                    });
                }
            }

            object Substitute(object value, Action<string> missing = null) {
                switch(value) {
                case IDictionary<string, object> map:
                    map = new Dictionary<string, object>(map.Select(kv => new KeyValuePair<string, object>(kv.Key, Substitute(kv.Value, missing))));
                    if(map.Count == 1) {

                        // handle !Ref expression
                        if(map.TryGetValue("Ref", out object refObject) && (refObject is string refKey)) {
                            if(TrySubstitute(refKey, null, out object found)) {
                                return found ?? map;
                            }
                            missing?.Invoke(refKey);
                            return map;
                        }

                        // handle !GetAtt expression
                        if(
                            map.TryGetValue("Fn::GetAtt", out object getAttObject)
                            && (getAttObject is IList<object> getAttArgs)
                            && (getAttArgs.Count == 2)
                            && getAttArgs[0] is string getAttKey
                            && getAttArgs[1] is string getAttAttribute
                        ) {
                            if(TrySubstitute(getAttKey, getAttAttribute, out object found)) {
                                return found ?? map;
                            }
                            missing?.Invoke(getAttKey);
                            return map;
                        }

                        // handle !Sub expression
                        if(map.TryGetValue("Fn::Sub", out object subObject)) {
                            string subPattern;
                            IDictionary<string, object> subArgs = null;

                            // determine which form of !Sub is being used
                            if(subObject is string) {
                                subPattern = (string)subObject;
                                subArgs = new Dictionary<string, object>();
                            } else if(
                                (subObject is IList<object> subList)
                                && (subList.Count == 2)
                                && (subList[0] is string)
                                && (subList[1] is IDictionary<string, object>)
                            ) {
                                subPattern = (string)subList[0];
                                subArgs = (IDictionary<string, object>)subList[1];
                            } else {
                                return map;
                            }

                            // replace as many ${VAR} occurrences as possible
                            var substitions = false;
                            subPattern = Regex.Replace(subPattern, SUBVARIABLE_PATTERN, match => {
                                var matchText = match.ToString();
                                var name = matchText.Substring(2, matchText.Length - 3).Trim().Split('.', 2);
                                if(!subArgs.ContainsKey(name[0])) {
                                    if(TrySubstitute(name[0], (name.Length == 2) ? name[1] : null, out object found)) {
                                        substitions = true;
                                        if(found == null) {
                                            return matchText;
                                        }
                                        if(found is string text) {
                                            return text;
                                        }
                                        var argName = $"P{subArgs.Count}";
                                        subArgs.Add(argName, found);
                                        return "${" + argName + "}";
                                    }
                                    missing?.Invoke(name[0]);
                                }
                                return matchText;
                            });
                            if(!substitions) {
                                return map;
                            }

                            // determine which form of !Sub to construct
                            return subArgs.Any()
                                ? FnSub(subPattern, subArgs)
                                : Regex.IsMatch(subPattern, SUBVARIABLE_PATTERN)
                                ? FnSub(subPattern)
                                : subPattern;
                        }
                    }
                    return map;
                case IList<object> list:
                    return list.Select(item => Substitute(item, missing)).ToList();
                case null:
                    AddError("null value is not allowed");
                    return value;
                default:

                    // nothing further to substitute
                    return value;
                }
            }

            bool TrySubstitute(string key, string attribute, out object found) {
                if(key.StartsWith("AWS::", StringComparison.Ordinal)) {
                    found = null;
                    return true;
                }
                key = key.Replace("::", "");
                found = null;
                if(freeParameters.TryGetValue(key, out AParameter freeParameter)) {
                    switch(freeParameter) {
                    case ValueParameter _:
                    case SecretParameter _:
                    case PackageParameter _:
                    case ValueListParameter _:
                    case ReferencedResourceParameter _:
                    case ValueInputParameter _:
                    case SecretInputParameter _:
                    case ImportInputParameter _:
                        if(attribute != null) {
                            AddError($"reference '{key}' must resolved to a CloudFormation resource to be used with an Fn::GetAtt expression");
                        }
                        found = freeParameter.Reference;
                        break;
                    case CloudFormationResourceParameter _:
                        found = (attribute != null)
                            ? FnGetAtt(key, attribute)
                            : freeParameter.Reference;
                        break;
                    }
                }
                return found != null;
            }
        }
    }
}