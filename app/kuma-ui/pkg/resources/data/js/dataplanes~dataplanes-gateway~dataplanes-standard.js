(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["dataplanes~dataplanes-gateway~dataplanes-standard"],{"0ac5":function(e,t,n){},"23d6":function(e,t,n){"use strict";n("b91b")},"275a":function(e,t,n){"use strict";n("0ac5")},"62e5":function(e,t){var n;n=function(){function e(e,t){var n,a,r,s,i,o,l,u,c;null==t&&(t=""),r="",i=e.length,o=null,a=0,s=0;while(s<i){if(n=e.charAt(s),"\\"===n)r+=e.slice(s,+(s+1)+1||9e9),s++;else if("("===n)if(s<i-2)if(u=e.slice(s,+(s+2)+1||9e9),"(?:"===u)s+=2,r+=u;else if("(?<"===u){a++,s+=2,l="";while(s+1<i){if(c=e.charAt(s+1),">"===c){r+="(",s++,l.length>0&&(null==o&&(o={}),o[l]=a);break}l+=c,s++}}else r+=n,a++;else r+=n;else r+=n;s++}this.rawRegex=e,this.cleanedRegex=r,this.regex=new RegExp(this.cleanedRegex,"g"+t.replace("g","")),this.mapping=o}return e.prototype.regex=null,e.prototype.rawRegex=null,e.prototype.cleanedRegex=null,e.prototype.mapping=null,e.prototype.exec=function(e){var t,n,a,r;if(this.regex.lastIndex=0,n=this.regex.exec(e),null==n)return null;if(null!=this.mapping)for(a in r=this.mapping,r)t=r[a],n[a]=n[t];return n},e.prototype.test=function(e){return this.regex.lastIndex=0,this.regex.test(e)},e.prototype.replace=function(e,t){return this.regex.lastIndex=0,e.replace(this.regex,t)},e.prototype.replaceAll=function(e,t,n){var a;null==n&&(n=0),this.regex.lastIndex=0,a=0;while(this.regex.test(e)&&(0===n||a<n))this.regex.lastIndex=0,e=e.replace(this.regex,t),a++;return[e,a]},e}(),e.exports=n},"63b5":function(e,t,n){"use strict";var a=function(){var e=this,t=e.$createElement,n=e._self._c||t;return n("KCard",{attrs:{"border-variant":"noBorder"},scopedSlots:e._u([{key:"body",fn:function(){return[n("ul",e._l(e.warnings,(function(t){var a=t.kind,r=t.payload,s=t.index;return n("li",{key:a+"/"+s,staticClass:"mb-1"},[n("KAlert",{attrs:{appearance:"warning"},scopedSlots:e._u([{key:"alertMessage",fn:function(){return[n(e.getWarningComponent(a),{tag:"component",attrs:{payload:r}})]},proxy:!0}],null,!0)})],1)})),0)]},proxy:!0}])})},r=[],s=function(){var e=this,t=e.$createElement,n=e._self._c||t;return n("span",[e._v(" "+e._s(e.payload)+" ")])},i=[],o={name:"WarningDefault",props:{payload:{type:[String,Object],required:!0}}},l=o,u=n("2877"),c=Object(u["a"])(l,s,i,!1,null,null,null),p=c.exports,d=function(){var e=this,t=e.$createElement,n=e._self._c||t;return n("span",[e._v(" Envoy ("),n("strong",[e._v(e._s(e.payload.envoy))]),e._v(") is unsupported by the current version of Kuma DP ("),n("strong",[e._v(e._s(e.payload.kumaDp))]),e._v(") [Requirements: "),n("strong",[e._v(" "+e._s(e.payload.requirements))]),e._v("] ")])},f=[],y={name:"WarningEnvoyIncompatible",props:{payload:{type:Object,required:!0}}},v=y,m=Object(u["a"])(v,d,f,!1,null,null,null),b=m.exports,h=function(){var e=this,t=e.$createElement,n=e._self._c||t;return n("span",[e._v(" There is mismatch between versions of Kuma DP ("),n("strong",[e._v(e._s(e.payload.kumaDpVersion))]),e._v(") and the Zone CP ("),n("strong",[e._v(e._s(e.payload.zoneVersion))]),e._v(") ")])},g=[],_={name:"WarningZoneAndKumaDPVersionsIncompatible",props:{payload:{type:Object,required:!0}}},x=_,E=Object(u["a"])(x,h,g,!1,null,null,null),k=E.exports,w=function(){var e=this,t=e.$createElement,n=e._self._c||t;return n("span",[e._v(" Unsupported version of Kuma DP ("),n("strong",[e._v(e._s(e.payload.kumaDpVersion))]),e._v(") ")])},C=[],S={name:"WarningUnsupportedKumaDPVersion",props:{payload:{type:Object,required:!0}}},T=S,O=Object(u["a"])(T,w,C,!1,null,null,null),j=O.exports,D=function(){var e=this,t=e.$createElement,n=e._self._c||t;return n("span",[e._v(" There is mismatch between versions of Zone CP ("),n("strong",[e._v(e._s(e.payload.zoneCpVersion))]),e._v(") and the Global CP ("),n("strong",[e._v(e._s(e.payload.globalCpVersion))]),e._v(") ")])},A=[],L={name:"WarningZoneAndGlobalCPSVersionsIncompatible",props:{payload:{type:Object,required:!0}}},P=L,I=Object(u["a"])(P,D,A,!1,null,null,null),R=I.exports,V=n("dbf3"),K={name:"Warnings",props:{warnings:{type:Array,required:!0}},methods:{getWarningComponent:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:"";switch(e){case V["b"]:return b;case V["c"]:return j;case V["f"]:return k;case V["e"]:return R;default:return p}}}},U=K,N=Object(u["a"])(U,a,r,!1,null,null,null);t["a"]=N.exports},"64cff":function(e,t,n){"use strict";n("7ac1")},6663:function(e,t,n){"use strict";var a=function(){var e=this,t=e.$createElement,n=e._self._c||t;return n("div",{staticClass:"entity-url-control"},[e.shouldDisplay?n("KClipboardProvider",{scopedSlots:e._u([{key:"default",fn:function(t){var a=t.copyToClipboard;return[n("KPop",{attrs:{placement:"bottom"},scopedSlots:e._u([{key:"content",fn:function(){return[n("div",[n("p",[e._v(e._s(e.confirmationText))])])]},proxy:!0}],null,!0)},[n("KButton",{attrs:{appearance:"secondary",size:"small"},on:{click:function(){a(e.url)}},scopedSlots:e._u([{key:"icon",fn:function(){return[n("KIcon",{attrs:{"view-box":"0 0 16 16",icon:"externalLink"}})]},proxy:!0}],null,!0)},[e._v(" "+e._s(e.copyButtonText)+" ")])],1)]}}],null,!1,244323940)}):e._e()],1)},r=[],s=n("a026"),i=s["a"].extend({name:"EntityURLControl",props:{url:{type:String,required:!0},copyButtonText:{type:String,default:"Copy URL"},confirmationText:{type:String,default:"URL copied to clipboard!"}},computed:{shouldDisplay:function(){var e=this.$route.params.mesh||null;return!(!e||"all"===e)}}}),o=i,l=n("2877"),u=Object(l["a"])(o,a,r,!1,null,null,null);t["a"]=u.exports},"6d8a":function(e,t,n){var a,r;r=n("62e5"),a=function(){var e;function t(){}return t.LIST_ESCAPEES=["\\","\\\\",'\\"','"',"\0","","","","","","","","\b","\t","\n","\v","\f","\r","","","","","","","","","","","","","","","","","","",(e=String.fromCharCode)(133),e(160),e(8232),e(8233)],t.LIST_ESCAPED=["\\\\",'\\"','\\"','\\"',"\\0","\\x01","\\x02","\\x03","\\x04","\\x05","\\x06","\\a","\\b","\\t","\\n","\\v","\\f","\\r","\\x0e","\\x0f","\\x10","\\x11","\\x12","\\x13","\\x14","\\x15","\\x16","\\x17","\\x18","\\x19","\\x1a","\\e","\\x1c","\\x1d","\\x1e","\\x1f","\\N","\\_","\\L","\\P"],t.MAPPING_ESCAPEES_TO_ESCAPED=function(){var e,n,a,r;for(a={},e=n=0,r=t.LIST_ESCAPEES.length;0<=r?n<r:n>r;e=0<=r?++n:--n)a[t.LIST_ESCAPEES[e]]=t.LIST_ESCAPED[e];return a}(),t.PATTERN_CHARACTERS_TO_ESCAPE=new r("[\\x00-\\x1f]|Â|Â |â¨|â©"),t.PATTERN_MAPPING_ESCAPEES=new r(t.LIST_ESCAPEES.join("|").split("\\").join("\\\\")),t.PATTERN_SINGLE_QUOTING=new r("[\\s'\":{}[\\],&*#?]|^[-?|<>=!%@`]"),t.requiresDoubleQuoting=function(e){return this.PATTERN_CHARACTERS_TO_ESCAPE.test(e)},t.escapeWithDoubleQuotes=function(e){var t;return t=this.PATTERN_MAPPING_ESCAPEES.replace(e,function(e){return function(t){return e.MAPPING_ESCAPEES_TO_ESCAPED[t]}}(this)),'"'+t+'"'},t.requiresSingleQuoting=function(e){return this.PATTERN_SINGLE_QUOTING.test(e)},t.escapeWithSingleQuotes=function(e){return"'"+e.replace(/'/g,"''")+"'"},t}(),e.exports=a},"7ac1":function(e,t,n){},"85e6":function(e,t,n){"use strict";var a=function(){var e=this,t=e.$createElement,n=e._self._c||t;return n("FrameSkeleton",[n("DataOverview",{attrs:{"page-size":e.pageSize,"has-error":e.hasError,"is-loading":e.isLoading,"empty-state":e.getEmptyState(),"table-data":e.buildTableData(),"table-data-is-empty":e.tableDataIsEmpty,"show-warnings":e.tableData.data.some((function(e){return e.withWarnings})),"table-data-function-text":"View","table-data-row":"name",next:e.next},on:{tableAction:e.tableAction,loadData:function(t){return e.loadData(t)}},scopedSlots:e._u([{key:"additionalControls",fn:function(){return[n("KButton",{staticClass:"add-dp-button",attrs:{appearance:"primary",size:"small",to:e.dataplaneWizardRoute},nativeOn:{click:function(t){return e.onCreateClick(t)}}},[n("span",{staticClass:"custom-control-icon"},[e._v(" + ")]),e._v(" Create data plane proxy ")]),e.$route.query.ns?n("KButton",{staticClass:"back-button",attrs:{appearance:"primary",size:"small",to:e.nsBackButtonRoute}},[n("span",{staticClass:"custom-control-icon"},[e._v(" ← ")]),e._v(" View All ")]):e._e()]},proxy:!0}])}),!1===e.isEmpty?n("Tabs",{attrs:{"has-error":e.hasError,"is-loading":e.isLoading,tabs:e.filterTabs(),"initial-tab-override":"overview"},scopedSlots:e._u([{key:"tabHeader",fn:function(){return[n("div",[n("h3",[e._v(e._s(e.tabGroupTitle))])]),n("div",[n("EntityURLControl",{attrs:{url:e.shareUrl}})],1)]},proxy:!0},{key:"overview",fn:function(){return[n("LabelList",{attrs:{"has-error":e.entityHasError,"is-loading":e.entityIsLoading,"is-empty":e.entityIsEmpty}},[n("div",[n("ul",e._l(e.entity.basicData,(function(t,a){return n("li",{key:a},[n("div","status"===a?[n("h4",[e._v(e._s(a))]),n("div",{staticClass:"entity-status",class:{"is-offline":"offline"===t.status.toString().toLowerCase()||!1===t.status,"is-degraded":"partially degraded"===t.status.toString().toLowerCase()||!1===t.status}},[n("span",{staticClass:"entity-status__label"},[e._v(e._s(t.status))])]),n("div",{staticClass:"reason-list"},[n("ul",e._l(t.reason,(function(t){return n("li",{key:t},[n("span",{staticClass:"entity-status__dot"}),e._v(" "+e._s(t)+" ")])})),0)])]:[n("h4",[e._v(e._s(a))]),e._v(" "+e._s(t)+" ")])])})),0)]),n("div",[n("h4",[e._v("Tags")]),n("p",e._l(e.entity.tags,(function(t,a){return n("span",{key:a,staticClass:"tag-cols"},[n("span",[e._v(" "+e._s(t.label)+": ")]),n("span",[e._v(" "+e._s(t.value)+" ")])])})),0)])])]},proxy:!0},e.showMtls?{key:"mtls",fn:function(){return[n("LabelList",{attrs:{"has-error":e.entityHasError,"is-loading":e.entityIsLoading,"is-empty":e.entityIsEmpty}},[e.entity.mtls?n("ul",e._l(e.entity.mtls,(function(t,a){return n("li",{key:a},[n("h4",[e._v(e._s(t.label))]),n("p",[e._v(" "+e._s(t.value)+" ")])])})),0):n("KAlert",{attrs:{appearance:"danger"},scopedSlots:e._u([{key:"alertMessage",fn:function(){return[e._v(" This data plane proxy does not yet have mTLS configured — "),n("a",{staticClass:"external-link",attrs:{href:"https://kuma.io/docs/"+e.version+"/documentation/security/#certificates",target:"_blank"}},[e._v(" Learn About Certificates in "+e._s(e.productName)+" ")])]},proxy:!0}],null,!1,672628330)})],1)]},proxy:!0}:null,{key:"yaml",fn:function(){return[n("YamlView",{attrs:{title:e.entityOverviewTitle,"has-error":e.entityHasError,"is-loading":e.entityIsLoading,"is-empty":e.entityIsEmpty,content:e.rawEntity}})]},proxy:!0},{key:"warnings",fn:function(){return[n("Warnings",{attrs:{warnings:e.warnings}})]},proxy:!0}],null,!0)}):e._e()],1)},r=[],s=(n("99af"),n("4de4"),n("7db0"),n("d81d"),n("13d5"),n("b0c0"),n("d3b7"),n("3ca3"),n("ddb0"),n("96cf"),n("c964")),i=n("f3f3"),o=n("2f62"),l=n("0f82"),u=n("027b"),c=n("bc1e"),p=n("75bb"),d=n("dbf3"),f=n("6663"),y=n("b912"),v=n("1d10"),m=n("2778"),b=n("251b"),h=n("ff9d"),g=n("0ada"),_=n("63b5"),x=n("c6ec"),E="kuma.io/zone",k={name:"Dataplanes",components:{Warnings:_["a"],EntityURLControl:f["a"],FrameSkeleton:v["a"],DataOverview:m["a"],Tabs:b["a"],YamlView:h["a"],LabelList:g["a"]},mixins:[y["a"]],props:{nsBackButtonRoute:{type:Object,default:function(){return{name:"dataplanes"}}},emptyStateMsg:{type:String,default:"There are no data plane proxies present."},dataplaneApiParams:{type:Object,default:function(){return{}}},tableHeaders:{type:Array,default:function(){return[{key:"actions",hideLabel:!0},{label:"Status",key:"status"},{label:"Name",key:"name"},{label:"Mesh",key:"mesh"},{label:"Type",key:"type"},{label:"Tags",key:"tags"},{label:"Last Connected",key:"lastConnected"},{label:"Last Updated",key:"lastUpdated"},{label:"Total Updates",key:"totalUpdates"},{label:"Kuma DP version",key:"dpVersion"},{label:"Envoy version",key:"envoyVersion"},{key:"warnings",hideLabel:!0}]}},tabs:{type:Array,default:function(){return[{hash:"#overview",title:"Overview"},{hash:"#mtls",title:"Certificate Insights"},{hash:"#yaml",title:"YAML"},{hash:"#warnings",title:"Warnings"}]}},showMtls:{type:Boolean,default:!0}},data:function(){return{productName:x["h"],isLoading:!0,isEmpty:!1,hasError:!1,entityIsLoading:!0,entityIsEmpty:!1,entityHasError:!1,warnings:[],tableDataIsEmpty:!1,tableData:{headers:[],data:[]},entity:[],rawEntity:null,firstEntity:null,pageSize:x["f"],next:null,tabGroupTitle:null,entityNamespace:null,entityOverviewTitle:null,shownTLSTab:!1}},computed:Object(i["a"])(Object(i["a"])({},Object(o["c"])({environment:"config/getEnvironment",queryNamespace:"getItemQueryNamespace",supportedVersions:"getSupportedVersions",supportedVersionsLoading:"getSupportedVersionsFetching",multicluster:"config/getMulticlusterStatus"})),{},{dataplaneWizardRoute:function(){return"universal"===this.environment?{name:"universal-dataplane"}:{name:"kubernetes-dataplane"}},version:function(){var e=this.$store.getters.getVersion;return null!==e?e:"latest"},shareUrl:function(){var e=this,t="".concat(window.location.origin,"/#"),n=this.entity,a=function(){return n.basicData?e.$route.query.ns?e.$route.fullPath:"".concat(t).concat(e.$route.fullPath,"?ns=").concat(n.basicData.name):null};return a()}}),watch:{$route:function(){this.loadData()}},beforeMount:function(){this.fetchSupportedVersions(),this.loadData()},methods:Object(i["a"])(Object(i["a"])({},Object(o["b"])(["fetchSupportedVersions"])),{},{onCreateClick:function(){u["a"].logger.info(p["a"].CREATE_DATA_PLANE_PROXY_CLICKED)},buildEntity:function(e,t,n){var a=n.mTLS?Object(d["o"])(n.mTLS):null;return{basicData:e,tags:t,mtls:a}},init:function(){this.loadData()},getEmptyState:function(){return{title:"No Data",message:this.emptyStateMsg}},filterTabs:function(){return this.warnings.length?this.tabs:this.tabs.filter((function(e){return"#warnings"!==e.hash}))},buildTableData:function(){return Object(i["a"])(Object(i["a"])({},this.tableData),{},{headers:this.tableHeaders})},checkVersionsCompatibility:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:"",t=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"";return Object(d["h"])(this.supportedVersions,e,t)},tableAction:function(e){var t=e;this.getEntity(t)},loadData:function(){var e=arguments,t=this;return Object(s["a"])(regeneratorRuntime.mark((function n(){var a,r,o,u,p,f,y,v,m,b,h,g;return regeneratorRuntime.wrap((function(n){while(1)switch(n.prev=n.next){case 0:return a=e.length>0&&void 0!==e[0]?e[0]:"0",t.isLoading=!0,r=t.$route.params.mesh||null,o=t.$route.query.ns||null,u=Object(i["a"])({size:t.pageSize,offset:a},t.dataplaneApiParams),p=function(){return"all"===r?l["a"].getAllDataplaneOverviews(u):o&&o.length&&"all"!==r?l["a"].getDataplaneOverviewFromMesh(r,o):l["a"].getAllDataplaneOverviewsFromMesh(r,u)},f=function(){var e=Object(s["a"])(regeneratorRuntime.mark((function e(n,a,r){var s,i,o,u,p,f,y,v,m,b,h,g,_,x,k,w,C,S,T,O,j,D,A,L,P,I,R,V,K,U;return regeneratorRuntime.wrap((function(e){while(1)switch(e.prev=e.next){case 0:return e.prev=0,e.next=3,l["a"].getDataplaneOverviewFromMesh(n,a);case 3:s=e.sent,i=s.dataplane,o=void 0===i?{}:i,u=s.dataplaneInsight,p=void 0===u?{}:u,f=s.name,y=void 0===f?"":f,v=s.mesh,m=void 0===v?"":v,b=p.subscriptions,h=void 0===b?[]:b,g=Object(d["i"])(o),_=Object(d["n"])(o,p),x=_.status,k={totalUpdates:0,totalRejectedUpdates:0,dpVersion:"-",envoyVersion:"-",selectedTime:NaN,selectedUpdateTime:NaN},w=h.reduce((function(e,t){var n=t.status,a=void 0===n?{}:n,r=t.connectTime,s=t.version,i=void 0===s?{}:s,o=a.total,l=void 0===o?{}:o,u=a.lastUpdateTime,c=l.responsesSent,p=void 0===c?"0":c,d=l.responsesRejected,f=void 0===d?"0":d,y=i.kumaDp,v=void 0===y?{}:y,m=i.envoy,b=void 0===m?{}:m,h=v.version,g=b.version,_=e.selectedTime,x=e.selectedUpdateTime,E=Date.parse(r),k=Date.parse(u);return E&&(!_||E>_)&&(_=E),k&&(!x||k>x)&&(x=k),{totalUpdates:e.totalUpdates+parseInt(p,10),totalRejectedUpdates:e.totalRejectedUpdates+parseInt(f,10),dpVersion:h||e.dpVersion,envoyVersion:g||e.envoyVersion,selectedTime:_,selectedUpdateTime:x}}),k),C=w.totalUpdates,S=w.totalRejectedUpdates,T=w.dpVersion,O=w.envoyVersion,j=w.selectedTime,D=w.selectedUpdateTime,A=j?Object(c["f"])(new Date(j).toUTCString()):"never",L=D?Object(c["f"])(new Date(D).toUTCString()):"never",P={name:y,mesh:m,tags:g,status:x,lastConnected:A,lastUpdated:L,totalUpdates:C,totalRejectedUpdates:S,dpVersion:T,envoyVersion:O,withWarnings:!1,unsupportedEnvoyVersion:!1,unsupportedKumaDPVersion:!1,kumaDpAndKumaCpMismatch:!1,type:Object(d["l"])(o)},I=t.checkVersionsCompatibility(T,O),R=I.kind,e.t0=R,e.next=e.t0===d["b"]?19:e.t0===d["c"]?22:25;break;case 19:return P.unsupportedEnvoyVersion=!0,P.withWarnings=!0,e.abrupt("break",25);case 22:return P.unsupportedKumaDPVersion=!0,P.withWarnings=!0,e.abrupt("break",25);case 25:if(!t.multicluster){e.next=39;break}if(V=g.find((function(e){return e.label===E})),!V){e.next=39;break}return e.prev=28,e.next=31,Object(d["g"])(V.value,T);case 31:K=e.sent,U=K.compatible,U||(P.withWarnings=!0,P.kumaDpAndKumaCpMismatch=!0),e.next=39;break;case 36:e.prev=36,e.t1=e["catch"](28),console.error(e.t1);case 39:return r.push(P),t.sortEntities(r),e.abrupt("return",r);case 44:e.prev=44,e.t2=e["catch"](0),console.error(e.t2);case 47:case"end":return e.stop()}}),e,null,[[0,44],[28,36]])})));return function(t,n,a){return e.apply(this,arguments)}}(),n.prev=7,n.next=10,p();case 10:if(y=n.sent,v=function(){var e=y;return"total"in e?0!==e.total&&e.items&&e.items.length>0?t.sortEntities(e.items):null:e},m=v(),!m){n.next=33;break}return t.next=Boolean(y.next),b=[],h=o?m:m[0],t.firstEntity=h.name,n.next=20,t.getEntity(h);case 20:if(!(o&&o.length&&r&&r.length)){n.next=25;break}return n.next=23,f(r,o,b);case 23:n.next=28;break;case 25:return g=m.map((function(e){return f(e.mesh,e.name,b)})),n.next=28,Promise.all(g);case 28:t.tableData.data=b,t.tableDataIsEmpty=!1,t.isEmpty=!1,n.next=38;break;case 33:return t.tableData.data=[],t.tableDataIsEmpty=!0,t.isEmpty=!0,n.next=38,t.getEntity(null);case 38:n.next=45;break;case 40:n.prev=40,n.t0=n["catch"](7),t.hasError=!0,t.isEmpty=!0,console.error(n.t0);case 45:setTimeout((function(){t.isLoading=!1}),"500");case 46:case"end":return n.stop()}}),n,null,[[7,40]])})))()},getEntity:function(e){var t=this;return Object(s["a"])(regeneratorRuntime.mark((function n(){var a,r,s,o,u,p,f,y,v,m,b,h,g,_,x,k,w,C,S,T,O,j,D,A;return regeneratorRuntime.wrap((function(n){while(1)switch(n.prev=n.next){case 0:if(t.entityIsLoading=!0,t.entityIsEmpty=!1,t.entityHasError=!1,a=t.$route.params.mesh,!e){n.next=56;break}return r="all"===a?e.mesh:a,n.prev=6,n.next=9,l["a"].getDataplaneOverviewFromMesh(r,e.name);case 9:if(s=n.sent,o=Object(d["j"])(s),!o){n.next=45;break}if(u=["type","name","mesh"],p=Object(d["k"])(s)||{},f=Object(d["n"])(o,p),y=Object(d["i"])(o),v=Object(i["a"])(Object(i["a"])({},Object(c["d"])(o,u)),{},{status:f}),t.entity=t.buildEntity(v,y,p),t.entityNamespace=v.name,t.tabGroupTitle="Mesh: ".concat(v.name),t.entityOverviewTitle="Entity Overview for ".concat(v.name),t.warnings=[],m=p.subscriptions,b=void 0===m?[]:m,!b.length){n.next=42;break}if(h=b.pop(),g=h.version,_=void 0===g?{}:g,x=_.kumaDp,k=void 0===x?{}:x,w=_.envoy,C=void 0===w?{}:w,k&&C&&(S=t.checkVersionsCompatibility(k.version,C.version),T=S.kind,T!==d["a"]&&T!==d["d"]&&t.warnings.push(S)),!t.multicluster){n.next=42;break}if(O=y.find((function(e){return e.label===E})),!O){n.next=42;break}return n.prev=30,n.next=33,Object(d["g"])(O.value,k.version);case 33:j=n.sent,D=j.compatible,A=j.payload,D||t.warnings.push({kind:d["f"],payload:A}),n.next=42;break;case 39:n.prev=39,n.t0=n["catch"](30),console.error(n.t0);case 42:t.rawEntity=Object(c["j"])(o),n.next=47;break;case 45:t.entity=null,t.entityIsEmpty=!0;case 47:n.next=53;break;case 49:n.prev=49,n.t1=n["catch"](6),t.entityHasError=!0,console.error(n.t1);case 53:setTimeout((function(){t.entityIsLoading=!1}),"500"),n.next=57;break;case 56:setTimeout((function(){t.entityIsEmpty=!0,t.entityIsLoading=!1}),"500");case 57:case"end":return n.stop()}}),n,null,[[6,49],[30,39]])})))()}})},w=k,C=(n("275a"),n("2877")),S=Object(C["a"])(w,a,r,!1,null,"29ad8878",null);t["a"]=S.exports},b912:function(e,t,n){"use strict";n("b0c0");t["a"]={methods:{sortEntities:function(e){var t=e.sort((function(e,t){return e.name>t.name||e.name===t.name&&e.mesh>t.mesh?1:-1}));return t}}}},b91b:function(e,t,n){},e80b:function(e,t,n){var a=n("6d8a"),r="  ";function s(e){var t=typeof e;return e instanceof Array?"array":"string"==t?"string":"boolean"==t?"boolean":"number"==t?"number":"undefined"==t||null===e?"null":"hash"}function i(e,t){var n=s(e);switch(n){case"array":o(e,t);break;case"hash":l(e,t);break;case"string":c(e,t);break;case"null":t.push("null");break;case"number":t.push(e.toString());break;case"boolean":t.push(e?"true":"false");break}}function o(e,t){for(var n=0;n<e.length;n++){var a=e[n],s=[];i(a,s);for(var o=0;o<s.length;o++)t.push((0==o?"- ":r)+s[o])}}function l(e,t){for(var n in e){var a=[];if(e.hasOwnProperty(n)){var o=e[n];i(o,a);var l=s(o);if("string"==l||"null"==l||"number"==l||"boolean"==l)t.push(u(n)+": "+a[0]);else{t.push(u(n)+": ");for(var c=0;c<a.length;c++)t.push(r+a[c])}}}}function u(e){return e.match(/^[\w]+$/)?e:a.requiresDoubleQuoting(e)?a.escapeWithDoubleQuotes(e):a.requiresSingleQuoting(e)?a.escapeWithSingleQuotes(e):e}function c(e,t){t.push(u(e))}var p=function(e){"string"==typeof e&&(e=JSON.parse(e));var t=[];return i(e,t),t.join("\n")};e.exports=p},ff9d:function(e,t,n){"use strict";var a=function(){var e=this,t=e.$createElement,n=e._self._c||t;return n("div",{staticClass:"yaml-view"},[e.isReady?n("div",{staticClass:"yaml-view-content"},[e.isLoading||e.isEmpty?e._e():n("KCard",{attrs:{title:e.title,"border-variant":"noBorder"},scopedSlots:e._u([{key:"body",fn:function(){return[n("KTabs",{key:e.environment,attrs:{tabs:e.tabs},scopedSlots:e._u([{key:"universal",fn:function(){return[n("KClipboardProvider",{scopedSlots:e._u([{key:"default",fn:function(t){var a=t.copyToClipboard;return[n("KPop",{attrs:{placement:"bottom"},scopedSlots:e._u([{key:"content",fn:function(){return[n("div",[n("p",[e._v("Entity copied to clipboard!")])])]},proxy:!0}],null,!0)},[n("KButton",{staticClass:"copy-button",attrs:{appearance:"primary",size:"small"},on:{click:function(){a(e.yamlContent.universal)}}},[e._v(" Copy Universal YAML ")])],1)]}}],null,!1,1536634960)}),n("prism",{staticClass:"code-block",attrs:{language:"yaml",code:e.yamlContent.universal}})]},proxy:!0},{key:"kubernetes",fn:function(){return[n("KClipboardProvider",{scopedSlots:e._u([{key:"default",fn:function(t){var a=t.copyToClipboard;return[n("KPop",{attrs:{placement:"bottom"},scopedSlots:e._u([{key:"content",fn:function(){return[n("div",[n("p",[e._v("Entity copied to clipboard!")])])]},proxy:!0}],null,!0)},[n("KButton",{staticClass:"copy-button",attrs:{appearance:"primary",size:"small"},on:{click:function(){a(e.yamlContent.kubernetes)}}},[e._v(" Copy Kubernetes YAML ")])],1)]}}],null,!1,2265429040)}),n("prism",{staticClass:"code-block",attrs:{language:"yaml",code:e.yamlContent.kubernetes}})]},proxy:!0}],null,!1,661975406),model:{value:e.activeTab.hash,callback:function(t){e.$set(e.activeTab,"hash",t)},expression:"activeTab.hash"}})]},proxy:!0}],null,!1,2034136171)})],1):e._e(),!0===e.loaders?n("div",[e.isLoading?n("KEmptyState",{attrs:{"cta-is-hidden":""},scopedSlots:e._u([{key:"title",fn:function(){return[n("div",{staticClass:"card-icon mb-3"},[n("KIcon",{attrs:{icon:"spinner",color:"rgba(0, 0, 0, 0.1)",size:"42"}})],1),e._v(" Data Loading... ")]},proxy:!0}],null,!1,3263214496)}):e._e(),e.isEmpty&&!e.isLoading?n("KEmptyState",{attrs:{"cta-is-hidden":""},scopedSlots:e._u([{key:"title",fn:function(){return[n("div",{staticClass:"card-icon mb-3"},[n("KIcon",{staticClass:"kong-icon--centered",attrs:{color:"var(--yellow-200)",icon:"warning","secondary-color":"var(--black-75)",size:"42"}})],1),e._v(" There is no data to display. ")]},proxy:!0}],null,!1,1612658095)}):e._e(),e.hasError?n("KEmptyState",{attrs:{"cta-is-hidden":""},scopedSlots:e._u([{key:"title",fn:function(){return[n("div",{staticClass:"card-icon mb-3"},[n("KIcon",{staticClass:"kong-icon--centered",attrs:{color:"var(--yellow-200)",icon:"warning","secondary-color":"var(--black-75)",size:"42"}})],1),e._v(" An error has occurred while trying to load this data. ")]},proxy:!0}],null,!1,822917942)}):e._e()],1):e._e()])},r=[],s=(n("caad"),n("a15b"),n("b0c0"),n("4fad"),n("ac1f"),n("2532"),n("1276"),n("f3f3")),i=n("2f62"),o=n("2ccf"),l=n.n(o),u=n("e80b"),c=n.n(u),p={name:"YamlView",components:{prism:l.a},props:{title:{type:String,default:null},content:{type:Object,default:null},loaders:{type:Boolean,default:!0},isLoading:{type:Boolean,default:!1},hasError:{type:Boolean,default:!1},isEmpty:{type:Boolean,default:!1}},data:function(){return{tabs:[{hash:"#universal",title:"Universal"},{hash:"#kubernetes",title:"Kubernetes"}]}},computed:Object(s["a"])(Object(s["a"])({},Object(i["c"])({environment:"config/getEnvironment"})),{},{isReady:function(){return!this.isEmpty&&!this.hasError&&!this.isLoading},activeTab:{get:function(){var e=this.environment;return{hash:"#".concat(e),nohash:e}},set:function(e){return{hash:"#".concat(e),nohash:e}}},yamlContent:function(){var e=this,t=this.content,n=function(){var t={},n=Object.assign({},e.content),a=n.name,r=n.mesh,s=n.type,i=function(){var t=Object.assign({},e.content);return delete t.type,delete t.mesh,delete t.name,!!(t&&Object.entries(t).length>0)&&t};if(t.apiVersion="kuma.io/v1alpha1",t.kind=s,void 0!==r&&(t.mesh=n.mesh),null!==a&&void 0!==a&&a.includes(".")){var o=a.split("."),l=o.pop(),u=o.join(".");t.metadata={name:u,namespace:l}}else t.metadata={name:a};return i()&&(t.spec=i()),t},a={universal:c()(t),kubernetes:c()(n())};return a}})},d=p,f=(n("23d6"),n("64cff"),n("2877")),y=Object(f["a"])(d,a,r,!1,null,"d189da22",null);t["a"]=y.exports}}]);