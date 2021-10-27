module.exports = function (time, iat) {
    var timestamp = iat || Math.floor(Date.now() / 1000);

    if (typeof time === 'number') {
        return timestamp + time;
    } else {
        return;
    }

};