const { utils } = require("ffjavascript");
const {stringifyBigInts, unstringifyBigInts} = utils;

const getTimestamp  = () => {
    return Math.round(Date.now() / 1000);
}

module.exports = {stringifyBigInts, getTimestamp};