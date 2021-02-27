const removeFalsy = (obj) => {
  let newObj = {};
  Object.keys(obj).forEach((prop) => {
    if (obj[prop]) {
      newObj[prop] = obj[prop];
    }
  });
  return newObj;
};

module.exports = removeFalsy;
