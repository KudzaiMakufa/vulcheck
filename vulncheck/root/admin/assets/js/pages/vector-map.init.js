! function(o) {
    "use strict";

    function r() {}
    r.prototype.init = function() { o("#world-map-markers").vectorMap({ map: "world_en", normalizeFunction: "polynomial", hoverOpacity: .7, hoverColor: !1, backgroundColor: "#transparent", color: "#f2f5f7", borderColor: "#bcbfc7", colors: { in: "#3d8ef8", au: "#3d8ef8", gl: "#3d8ef8", us: "#3d8ef8", sa: "#3d8ef8" }, borderColors: { in: "#3d8ef8", au: "#3d8ef8", gl: "#3d8ef8", us: "#3d8ef8", sa: "#3d8ef8" } }), o("#usa").vectorMap({ map: "usa_en", enableZoom: !0, showTooltip: !0, selectedColor: null, hoverColor: "#5b9ff9", backgroundColor: "transparent", color: "#3d8ef8", borderColor: "#bcbfc7", colors: { ca: "#5b9ff9", tx: "#5b9ff9", mt: "#5b9ff9", ny: "#5b9ff9" }, onRegionClick: function(o, r, e) { o.preventDefault() } }), o("#canada").vectorMap({ map: "canada_en", backgroundColor: "transparent", color: "#3d8ef8", hoverColor: "#5b9ff9", borderColor: "#bcbfc7", enableZoom: !0, showTooltip: !0 }), o("#france").vectorMap({ map: "france_fr", backgroundColor: "transparent", color: "#3d8ef8", borderColor: "#bcbfc7", hoverColor: "#5b9ff9", enableZoom: !0, showTooltip: !0 }), o("#germany").vectorMap({ map: "germany_en", backgroundColor: "transparent", color: "#3d8ef8", borderColor: "#bcbfc7", hoverColor: "#5b9ff9", enableZoom: !0, showTooltip: !0 }), o("#brazil").vectorMap({ map: "brazil_br", backgroundColor: "transparent", color: "#3d8ef8", borderColor: "#bcbfc7", hoverColor: "#5b9ff9", enableZoom: !0, showTooltip: !0 }) }, o.VectorMap = new r, o.VectorMap.Constructor = r
}(window.jQuery),
function() {
    "use strict";
    window.jQuery.VectorMap.init()
}();