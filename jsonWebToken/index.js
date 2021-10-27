module.exports = {
    verify: require('./verify'),
    sign: require('./sign'),
};

Object.defineProperty(module.exports, 'decode', {
    enumerable: false,
    value: require('./decode'),
});
