(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["wizard-mesh"],{1373:function(e,a,t){"use strict";t("99af");var n=t("e80b"),i=t.n(n);a["a"]={methods:{formatForCLI:function(e){var a=arguments.length>1&&void 0!==arguments[1]?arguments[1]:'" | kumactl apply -f -',t='echo "',n=i()(e);return"".concat(t).concat(n).concat(a)}}}},4190:function(e,a,t){"use strict";t.r(a);var n=function(){var e=this,a=e.$createElement,t=e._self._c||a;return t("div",{staticClass:"wizard"},[t("div",{staticClass:"wizard__content"},[t("StepSkeleton",{attrs:{steps:e.steps,"sidebar-content":e.sidebarContent,"footer-enabled":!1===e.hideScannerSiblings,"next-disabled":e.nextDisabled},scopedSlots:e._u([{key:"general",fn:function(){return[t("p",[e._v(" Welcome to the wizard for creating a new Mesh resource in "+e._s(e.productName)+". We will be providing you with a few steps that will get you started. ")]),t("p",[e._v(" As you know, the "+e._s(e.productName)+" GUI is read-only, so at the end of this wizard we will be generating the configuration that you can apply with either "),t("code",[e._v("kubectl")]),e._v(" (if you are running in Kubernetes mode) or "),t("code",[e._v("kumactl")]),e._v(" / API (if you are running in Universal mode). ")]),t("h3",[e._v(" To get started, please fill in the following information: ")]),t("KCard",{staticClass:"my-6 k-card--small",attrs:{title:"Mesh Information","has-shadow":""},scopedSlots:e._u([{key:"body",fn:function(){return[t("FormFragment",{attrs:{title:"Mesh name","for-attr":"mesh-name"}},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshName,expression:"validate.meshName"}],staticClass:"k-input w-100",attrs:{id:"mesh-name",type:"text",placeholder:"your-mesh-name",required:""},domProps:{value:e.validate.meshName},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshName",a.target.value)}}}),e.vmsg.meshName?t("KAlert",{attrs:{appearance:"danger",size:"small","alert-message":e.vmsg.meshName}}):e._e()],1),t("FormFragment",{attrs:{title:"Mutual TLS"}},[t("label",{staticClass:"k-input-label mx-2"},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.mtlsEnabled,expression:"validate.mtlsEnabled"}],ref:"mtlsDisabled",staticClass:"k-input mr-2",attrs:{value:"disabled",name:"mtls",type:"radio"},domProps:{checked:e._q(e.validate.mtlsEnabled,"disabled")},on:{change:function(a){return e.$set(e.validate,"mtlsEnabled","disabled")}}}),t("span",[e._v("Disabled")])]),t("label",{staticClass:"k-input-label mx-2"},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.mtlsEnabled,expression:"validate.mtlsEnabled"}],staticClass:"k-input mr-2",attrs:{id:"mtls-enabled",value:"enabled",name:"mtls",type:"radio"},domProps:{checked:e._q(e.validate.mtlsEnabled,"enabled")},on:{change:function(a){return e.$set(e.validate,"mtlsEnabled","enabled")}}}),t("span",[e._v("Enabled")])])]),"enabled"===e.validate.mtlsEnabled?t("FormFragment",{attrs:{title:"Certificate name","for-attr":"certificate-name"}},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshCAName,expression:"validate.meshCAName"}],staticClass:"k-input w-100",attrs:{id:"certificate-name",type:"text",placeholder:"your-certificate-name"},domProps:{value:e.validate.meshCAName},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshCAName",a.target.value)}}})]):e._e(),"enabled"===e.validate.mtlsEnabled?t("FormFragment",{attrs:{title:"Certificate Authority","for-attr":"certificate-authority"}},[t("select",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshCA,expression:"validate.meshCA"}],staticClass:"k-input w-100",attrs:{id:"certificate-authority",name:"certificate-authority"},on:{change:function(a){var t=Array.prototype.filter.call(a.target.options,(function(e){return e.selected})).map((function(e){var a="_value"in e?e._value:e.value;return a}));e.$set(e.validate,"meshCA",a.target.multiple?t:t[0])}}},[t("option",{attrs:{value:"builtin"}},[e._v(" builtin ")]),t("option",{attrs:{value:"provided"}},[e._v(" provided ")]),t("option",{attrs:{value:"vault"}},[e._v(" vault ")])]),t("p",{staticClass:"help"},[e._v(" If you've enabled mTLS, you must select a CA. ")])]):e._e()]},proxy:!0}])})]},proxy:!0},{key:"logging",fn:function(){return[t("h3",[e._v(" Setup Logging ")]),t("p",[e._v(' You can setup as many logging backends as you need that you can later use to log traffic via the "TrafficLog" policy. In this wizard, we allow you to configure one backend, but you can add more manually if you wish. ')]),t("KCard",{staticClass:"my-6 k-card--small",attrs:{title:"Logging Configuration","has-shadow":""},scopedSlots:e._u([{key:"body",fn:function(){return[t("FormFragment",{attrs:{title:"Logging"}},[t("label",{staticClass:"k-input-label mx-2"},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.loggingEnabled,expression:"validate.loggingEnabled"}],staticClass:"k-input mr-2",attrs:{id:"logging-disabled",value:"disabled",name:"logging",type:"radio"},domProps:{checked:e._q(e.validate.loggingEnabled,"disabled")},on:{change:function(a){return e.$set(e.validate,"loggingEnabled","disabled")}}}),t("span",[e._v("Disabled")])]),t("label",{staticClass:"k-input-label mx-2"},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.loggingEnabled,expression:"validate.loggingEnabled"}],staticClass:"k-input mr-2",attrs:{id:"logging-enabled",value:"enabled",name:"logging",type:"radio"},domProps:{checked:e._q(e.validate.loggingEnabled,"enabled")},on:{change:function(a){return e.$set(e.validate,"loggingEnabled","enabled")}}}),t("span",[e._v("Enabled")])])]),"enabled"===e.validate.loggingEnabled?t("FormFragment",{attrs:{title:"Backend name","for-attr":"backend-name"}},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshLoggingBackend,expression:"validate.meshLoggingBackend"}],staticClass:"k-input w-100",attrs:{id:"backend-name",type:"text",placeholder:"your-backend-name"},domProps:{value:e.validate.meshLoggingBackend},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshLoggingBackend",a.target.value)}}})]):e._e(),"enabled"===e.validate.loggingEnabled?t("div",[t("FormFragment",{attrs:{title:"Type"}},[t("select",{directives:[{name:"model",rawName:"v-model",value:e.validate.loggingType,expression:"validate.loggingType"}],ref:"loggingTypeSelect",staticClass:"k-input w-100",attrs:{id:"logging-type",name:"logging-type"},on:{change:function(a){var t=Array.prototype.filter.call(a.target.options,(function(e){return e.selected})).map((function(e){var a="_value"in e?e._value:e.value;return a}));e.$set(e.validate,"loggingType",a.target.multiple?t:t[0])}}},[t("option",{attrs:{value:"tcp"}},[e._v(" TCP ")]),t("option",{attrs:{value:"file"}},[e._v(" File ")])])]),"file"===e.validate.loggingType?t("FormFragment",{attrs:{title:"Path","for-attr":"backend-address"}},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshLoggingPath,expression:"validate.meshLoggingPath"}],staticClass:"k-input w-100",attrs:{id:"backend-address",type:"text"},domProps:{value:e.validate.meshLoggingPath},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshLoggingPath",a.target.value)}}})]):e._e(),"tcp"===e.validate.loggingType?t("FormFragment",{attrs:{title:"Address","for-attr":"backend-address"}},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshLoggingAddress,expression:"validate.meshLoggingAddress"}],staticClass:"k-input w-100",attrs:{id:"backend-address",type:"text"},domProps:{value:e.validate.meshLoggingAddress},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshLoggingAddress",a.target.value)}}})]):e._e(),t("FormFragment",{attrs:{title:"Format","for-attr":"backend-format"}},[t("textarea",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshLoggingBackendFormat,expression:"validate.meshLoggingBackendFormat"}],staticClass:"k-input w-100 code-sample",attrs:{id:"backend-format",rows:"12"},domProps:{value:e.validate.meshLoggingBackendFormat},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshLoggingBackendFormat",a.target.value)}}})])],1):e._e()]},proxy:!0}])})]},proxy:!0},{key:"tracing",fn:function(){return[t("h3",[e._v(" Setup Tracing ")]),t("p",[e._v(' You can setup as many tracing backends as you need that you can later use to log traffic via the "TrafficTrace" policy. In this wizard we allow you to configure one backend, but you can add more manually as you wish. ')]),t("KCard",{staticClass:"my-6 k-card--small",attrs:{title:"Tracing Configuration","has-shadow":""},scopedSlots:e._u([{key:"body",fn:function(){return[t("FormFragment",{attrs:{title:"Tracing"}},[t("label",{staticClass:"k-input-label mx-2"},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.tracingEnabled,expression:"validate.tracingEnabled"}],staticClass:"k-input mr-2",attrs:{id:"tracing-disabled",value:"disabled",name:"tracing",type:"radio"},domProps:{checked:e._q(e.validate.tracingEnabled,"disabled")},on:{change:function(a){return e.$set(e.validate,"tracingEnabled","disabled")}}}),t("span",[e._v("Disabled")])]),t("label",{staticClass:"k-input-label mx-2"},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.tracingEnabled,expression:"validate.tracingEnabled"}],staticClass:"k-input mr-2",attrs:{id:"tracing-enabled",value:"enabled",name:"tracing",type:"radio"},domProps:{checked:e._q(e.validate.tracingEnabled,"enabled")},on:{change:function(a){return e.$set(e.validate,"tracingEnabled","enabled")}}}),t("span",[e._v("Enabled")])])]),"enabled"===e.validate.tracingEnabled?t("FormFragment",{attrs:{title:"Backend name","for-attr":"tracing-backend-name"}},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshTracingBackend,expression:"validate.meshTracingBackend"}],staticClass:"k-input w-100",attrs:{id:"tracing-backend-name",type:"text",placeholder:"your-tracing-backend-name"},domProps:{value:e.validate.meshTracingBackend},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshTracingBackend",a.target.value)}}})]):e._e(),"enabled"===e.validate.tracingEnabled?t("FormFragment",{attrs:{title:"Type","for-attr":"tracing-type"}},[t("select",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshTracingType,expression:"validate.meshTracingType"}],staticClass:"k-input w-100",attrs:{id:"tracing-type",name:"tracing-type"},on:{change:function(a){var t=Array.prototype.filter.call(a.target.options,(function(e){return e.selected})).map((function(e){var a="_value"in e?e._value:e.value;return a}));e.$set(e.validate,"meshTracingType",a.target.multiple?t:t[0])}}},[t("option",{attrs:{value:"zipkin"}},[e._v(" Zipkin ")])])]):e._e(),"enabled"===e.validate.tracingEnabled?t("FormFragment",{attrs:{title:"Sampling","for-attr":"tracing-sampling"}},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshTracingSampling,expression:"validate.meshTracingSampling"}],staticClass:"k-input w-100",attrs:{id:"tracing-sampling",type:"number",step:"0.1",min:"0",max:"100"},domProps:{value:e.validate.meshTracingSampling},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshTracingSampling",a.target.value)}}})]):e._e(),"enabled"===e.validate.tracingEnabled?t("FormFragment",{attrs:{title:"URL","for-attr":"tracing-zipkin-url"}},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshTracingZipkinURL,expression:"validate.meshTracingZipkinURL"}],staticClass:"k-input w-100",attrs:{id:"tracing-zipkin-url",type:"text",placeholder:"http://zipkin.url:1234"},domProps:{value:e.validate.meshTracingZipkinURL},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshTracingZipkinURL",a.target.value)}}})]):e._e()]},proxy:!0}])})]},proxy:!0},{key:"metrics",fn:function(){return[t("h3",[e._v(" Setup Metrics ")]),t("p",[e._v(" You can expose metrics from every data-plane on a configurable path and port that a metrics service, like Prometheus, can use to fetch them. ")]),t("KCard",{staticClass:"my-6 k-card--small",attrs:{title:"Metrics Configuration","has-shadow":""},scopedSlots:e._u([{key:"body",fn:function(){return[t("FormFragment",{attrs:{title:"Metrics"}},[t("label",{staticClass:"k-input-label mx-2"},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.metricsEnabled,expression:"validate.metricsEnabled"}],staticClass:"k-input mr-2",attrs:{id:"metrics-disabled",value:"disabled",name:"metrics",type:"radio"},domProps:{checked:e._q(e.validate.metricsEnabled,"disabled")},on:{change:function(a){return e.$set(e.validate,"metricsEnabled","disabled")}}}),t("span",[e._v("Disabled")])]),t("label",{staticClass:"k-input-label mx-2"},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.metricsEnabled,expression:"validate.metricsEnabled"}],staticClass:"k-input mr-2",attrs:{id:"metrics-enabled",value:"enabled",name:"metrics",type:"radio"},domProps:{checked:e._q(e.validate.metricsEnabled,"enabled")},on:{change:function(a){return e.$set(e.validate,"metricsEnabled","enabled")}}}),t("span",[e._v("Enabled")])])]),"enabled"===e.validate.metricsEnabled?t("FormFragment",{attrs:{title:"Backend name","for-attr":"metrics-name"}},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshMetricsName,expression:"validate.meshMetricsName"}],staticClass:"k-input w-100",attrs:{id:"metrics-name",type:"text",placeholder:"your-metrics-backend-name"},domProps:{value:e.validate.meshMetricsName},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshMetricsName",a.target.value)}}})]):e._e(),"enabled"===e.validate.metricsEnabled?t("FormFragment",{attrs:{title:"Type","for-attr":"metrics-type"}},[t("select",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshMetricsType,expression:"validate.meshMetricsType"}],staticClass:"k-input w-100",attrs:{id:"metrics-type",name:"metrics-type"},on:{change:function(a){var t=Array.prototype.filter.call(a.target.options,(function(e){return e.selected})).map((function(e){var a="_value"in e?e._value:e.value;return a}));e.$set(e.validate,"meshMetricsType",a.target.multiple?t:t[0])}}},[t("option",{attrs:{value:"prometheus"}},[e._v(" Prometheus ")])])]):e._e(),"enabled"===e.validate.metricsEnabled?t("FormFragment",{attrs:{title:"Dataplane port","for-attr":"metrics-dataplane-port"}},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshMetricsDataplanePort,expression:"validate.meshMetricsDataplanePort"}],staticClass:"k-input w-100",attrs:{id:"metrics-dataplane-port",type:"number",step:"1",min:"0",max:"65535",placeholder:"1234"},domProps:{value:e.validate.meshMetricsDataplanePort},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshMetricsDataplanePort",a.target.value)}}})]):e._e(),"enabled"===e.validate.metricsEnabled?t("FormFragment",{attrs:{title:"Dataplane path","for-attr":"metrics-dataplane-path"}},[t("input",{directives:[{name:"model",rawName:"v-model",value:e.validate.meshMetricsDataplanePath,expression:"validate.meshMetricsDataplanePath"}],staticClass:"k-input w-100",attrs:{id:"metrics-dataplane-path",type:"text"},domProps:{value:e.validate.meshMetricsDataplanePath},on:{input:function(a){a.target.composing||e.$set(e.validate,"meshMetricsDataplanePath",a.target.value)}}})]):e._e()]},proxy:!0}])})]},proxy:!0},{key:"complete",fn:function(){return[e.codeOutput?t("div",[!1===e.hideScannerSiblings?t("div",[t("h3",[e._v(" Install a new Mesh ")]),t("p",[e._v(" Since the "+e._s(e.productName)+" GUI is read-only mode to follow Ops best practices, please execute the following command in your shell to create the entity. "+e._s(e.productName)+" will automatically detect when the new entity has been created. ")]),t("Tabs",{attrs:{loaders:!1,tabs:e.tabs,"has-border":!0,"initial-tab-override":e.environment},on:{onTabChange:e.onTabChange},scopedSlots:e._u([{key:"kubernetes",fn:function(){return[t("CodeView",{attrs:{title:"Kubernetes","copy-button-text":"Copy Command to Clipboard",lang:"bash",content:e.codeOutput}})]},proxy:!0},{key:"universal",fn:function(){return[t("CodeView",{attrs:{title:"Universal","copy-button-text":"Copy Command to Clipboard",lang:"bash",content:e.codeOutput}})]},proxy:!0}],null,!1,2548625193)})],1):e._e(),t("Scanner",{attrs:{"loader-function":e.scanForEntity,"should-start":!0,"has-error":e.scanError,"can-complete":e.scanFound},on:{hideSiblings:e.hideSiblings},scopedSlots:e._u([{key:"loading-title",fn:function(){return[t("h3",[e._v("Searching…")])]},proxy:!0},{key:"loading-content",fn:function(){return[t("p",[e._v("We are looking for your mesh.")])]},proxy:!0},{key:"complete-title",fn:function(){return[t("h3",[e._v("Done!")])]},proxy:!0},{key:"complete-content",fn:function(){return[t("p",[e._v(" Your Mesh "),e.validate.meshName?t("strong",[e._v(e._s(e.validate.meshName))]):e._e(),e._v(" was found! ")]),t("p",[t("KButton",{attrs:{appearance:"primary",to:{name:"all-meshes"}}},[e._v(" See Meshes ")])],1)]},proxy:!0},{key:"error-title",fn:function(){return[t("h3",[e._v("Mesh not found")])]},proxy:!0},{key:"error-content",fn:function(){return[t("p",[e._v("We were unable to find your mesh.")])]},proxy:!0}],null,!1,293133655)})],1):t("KAlert",{attrs:{appearance:"danger"},scopedSlots:e._u([{key:"alertMessage",fn:function(){return[t("p",[e._v(" You haven't filled any data out yet! Please return to the first step and fill out your information. ")])]},proxy:!0}])})]},proxy:!0},{key:"mesh",fn:function(){return[t("h3",[e._v("Mesh")]),t("p",[e._v(" In "+e._s(e.title)+", a Mesh resource allows you to define an isolated environment for your data-planes and policies. It's isolated because the mTLS CA you choose can be different from the one configured for our Meshes. Ideally, you will have either a large Mesh with all the workloads, or one Mesh per application for better isolation. ")]),t("p",[t("a",{attrs:{href:"https://kuma.io/docs/"+e.version+"/policies/mesh/"+e.utm,target:"_blank"}},[e._v(" Learn More ")])])]},proxy:!0},{key:"did-you-know",fn:function(){return[t("h3",[e._v("Did You Know?")]),t("p",[e._v(" As you know, the GUI is read-only, but it will be providing instructions to create a new Mesh and verify everything worked well. ")])]},proxy:!0}])})],1)])},i=[],s=(t("4de4"),t("4160"),t("b0c0"),t("4fad"),t("d3b7"),t("159b"),t("f3f3")),r=t("2f62"),l=t("0f82"),o=(t("caad"),t("d81d"),t("13d5"),t("b64b"),t("2532"),t("fc11"));function d(e,a){return Object.keys(e).filter((function(e){return!a.includes(e)})).map((function(a){return Object.assign({},Object(o["a"])({},a,e[a]))})).reduce((function(e,a){return Object.assign(e,a)}),{})}var c=t("bc1e"),m=t("1373"),u=t("2791"),g=t("251b"),p=t("4c4d"),v=t("12d5"),h=t("c3b5"),b=t("6c09"),f=t.n(b),y=t("c6ec"),k={name:"MeshWizard",metaInfo:{title:"Create a new Mesh"},components:{FormFragment:u["a"],Tabs:g["a"],StepSkeleton:p["a"],CodeView:v["a"],Scanner:h["a"]},mixins:[m["a"]],data:function(){return{productName:y["g"],selectedTab:"",schema:f.a,steps:[{label:"General & Security",slug:"general"},{label:"Logging",slug:"logging"},{label:"Tracing",slug:"tracing"},{label:"Metrics",slug:"metrics"},{label:"Install",slug:"complete"}],tabs:[{hash:"#kubernetes",title:"Kubernetes"},{hash:"#universal",title:"Universal"}],sidebarContent:[{name:"mesh"},{name:"did-you-know"}],formConditions:{mtlsEnabled:!1,loggingEnabled:!1,tracingEnabled:!1,metricsEnabled:!1,loggingType:null},startScanner:!1,scanFound:!1,hideScannerSiblings:!1,scanError:!1,isComplete:!1,validate:{meshName:"",meshCAName:"",meshLoggingBackend:"",meshTracingBackend:"",meshMetricsName:"",meshTracingZipkinURL:"",mtlsEnabled:"disabled",meshCA:"builtin",loggingEnabled:"disabled",loggingType:"tcp",meshLoggingPath:"/",meshLoggingAddress:"127.0.0.1:5000",meshLoggingBackendFormat:"{ start_time: '%START_TIME%', source: '%KUMA_SOURCE_SERVICE%', destination: '%KUMA_DESTINATION_SERVICE%', source_address: '%KUMA_SOURCE_ADDRESS_WITHOUT_PORT%', destination_address: '%UPSTREAM_HOST%', duration_millis: '%DURATION%', bytes_received: '%BYTES_RECEIVED%', bytes_sent: '%BYTES_SENT%' }",tracingEnabled:"disabled",meshTracingType:"zipkin",meshTracingSampling:99.9,metricsEnabled:"disabled",meshMetricsType:"prometheus",meshMetricsDataplanePort:5670,meshMetricsDataplanePath:"/metrics"},vmsg:[],utm:"?utm_source=Kuma&utm_medium=Kuma-GUI"}},computed:Object(s["a"])(Object(s["a"])({},Object(r["c"])({title:"config/getTagline",version:"config/getVersion",environment:"config/getEnvironment"})),{},{codeOutput:function(){var e=this.schema,a=Object.assign({},e),t=this.validate;if(t){var n="enabled"===t.mtlsEnabled,i="enabled"===t.loggingEnabled,r="enabled"===t.tracingEnabled,l="enabled"===t.metricsEnabled,o={mtls:n,logging:i,tracing:r,metrics:l},c=[];if(Object.entries(o).forEach((function(e){var a=e[1],t=e[0];a?c.filter((function(e){return e!==t})):c.push(t)})),n){a.mtls.enabled=!0;var m=a.mtls,u=this.validate.meshCA,g=this.validate.meshCAName;m.backends=[],m.enabledBackend=g,m.backends="provided"===u?[{name:g,type:u,conf:{cert:{secret:""},key:{secret:""}}}]:[{name:g,type:u}]}if(i){var p=a.logging.backends[0],v=p.format;p.conf={},p.name=t.meshLoggingBackend,p.type=t.loggingType,p.format=t.meshLoggingBackendFormat||v,"tcp"===t.loggingType?p.conf.address=t.meshLoggingAddress||"127.0.0.1:5000":"file"===t.loggingType&&(p.conf.path=t.meshLoggingPath)}if(r){var h=a.tracing;h.backends[0].conf={},h.defaultBackend=t.meshTracingBackend,h.backends[0].type=t.meshTracingType||"zipkin",h.backends[0].name=t.meshTracingBackend,h.backends[0].conf.sampling=t.meshTracingSampling||100,h.backends[0].conf.url=t.meshTracingZipkinURL}if(l){var b=a.metrics;b.backends[0].conf={},b.enabledBackend=t.meshMetricsName,b.backends[0].type=t.meshMetricsType||"prometheus",b.backends[0].name=t.meshMetricsName,b.backends[0].conf.port=t.meshMetricsDataplanePort||5670,b.backends[0].conf.path=t.meshMetricsDataplanePath||"/metrics"}var f,y=d(a,c);return f="#kubernetes"===this.selectedTab?{apiVersion:"kuma.io/v1alpha1",kind:"Mesh",metadata:{name:t.meshName},spec:y}:Object(s["a"])({type:"Mesh",name:t.meshName},y),this.formatForCLI(f,'" | kumactl apply -f -')}},nextDisabled:function(){var e=this.validate,a=e.meshName,t=e.meshCAName,n=e.meshLoggingBackend,i=e.meshTracingBackend,s=e.meshTracingZipkinURL,r=e.meshMetricsName,l=e.mtlsEnabled,o=e.loggingEnabled,d=e.tracingEnabled,c=e.metricsEnabled,m=e.meshLoggingPath,u=e.loggingType;return!a.length||"enabled"===l&&!t||("1"===this.$route.query.step?"disabled"!==o&&(!n||"file"===u&&!m):"2"===this.$route.query.step?"enabled"===d&&!(i&&s):"3"===this.$route.query.step&&("enabled"===c&&!r))}}),watch:{"validate.meshName":function(e){var a=Object(c["h"])(e);this.validate.meshName=a,this.validateMeshName(a)},"validate.meshCAName":function(e){this.validate.meshCAName=Object(c["h"])(e)},"validate.meshLoggingBackend":function(e){this.validate.meshLoggingBackend=Object(c["h"])(e)},"validate.meshTracingBackend":function(e){this.validate.meshTracingBackend=Object(c["h"])(e)},"validate.meshMetricsName":function(e){this.validate.meshMetricsName=Object(c["h"])(e)}},methods:{onTabChange:function(e){this.selectedTab=e},hideSiblings:function(){this.hideScannerSiblings=!0},validateMeshName:function(e){this.vmsg.meshName=e&&""!==e?"":"A Mesh name is required to proceed"},scanForEntity:function(){var e=this,a=this.validate.meshName;this.scanComplete=!1,this.scanError=!1,a&&l["a"].getMesh(a).then((function(a){a&&a.name.length>0?(e.isRunning=!0,e.scanFound=!0):e.scanError=!0})).catch((function(a){e.scanError=!0,console.error(a)})).finally((function(){e.scanComplete=!0}))}}},_=k,E=t("2877"),w=Object(E["a"])(_,n,i,!1,null,null,null);a["default"]=w.exports},"6c09":function(e,a,t){"use strict";e.exports={mtls:{enabledBackend:null,backends:[]},tracing:{defaultBackend:null,backends:[{name:null,type:null}]},logging:{backends:[{name:null,format:'{ "destination": "%KUMA_DESTINATION_SERVICE%", "destinationAddress": "%UPSTREAM_LOCAL_ADDRESS%", "source": "%KUMA_SOURCE_SERVICE%", "sourceAddress": "%KUMA_SOURCE_ADDRESS%", "bytesReceived": "%BYTES_RECEIVED%", "bytesSent": "%BYTES_SENT%"}',type:null}]},metrics:{enabledBackend:null,backends:[{name:null,type:null}]}}}}]);