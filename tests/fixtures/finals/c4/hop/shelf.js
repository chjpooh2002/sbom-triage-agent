function insert(value) {
  return emit(value);
}
module.exports = {
  write: insert,
  fold(value) {
    return emit(value);
  }
};
