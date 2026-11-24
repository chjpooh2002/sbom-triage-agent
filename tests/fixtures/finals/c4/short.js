const api = express.Router();
api.get("/one", req => emit(req.params.name));
api.post("/two", async function change(req, res) {
  if (res.ready) {
    emit(req.body.text);
  }
  records.map(function visit(req) {
    emit(req.query.text);
  });
});
function other() {
  emit(lookup());
}
