function getGlobal() {
    if (typeof globalThis !== 'undefined')
        return globalThis;
    if (typeof self !== 'undefined')
        return self;
    if (typeof window !== 'undefined')
        return window;
    throw new Error('unable to locate global object');
}

module.exports = getGlobal();
module.exports.isCloudflareWorkers = function isCloudflareWorkers() {
    try {
        return getGlobal().WebSocketPair !== undefined;
    } catch (_a) {
        return false;
    }
}
module.exports.isNodeJs = function isNodeJs() {
    var _a, _b;
    try {
        return ((_b = (_a = getGlobal().process) === null || _a === void 0 ? void 0 : _a.versions) === null || _b === void 0 ? void 0 : _b.node) !== undefined;
    } catch (_c) {
        return false;
    }
}
