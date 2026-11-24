import {
  emit
} from "@paper/kit/format";
const helper = require("folio/util");
// require("unused");
const example = "require('unused')";
router.post("/entry", (input, reply) => {
  const phrase = input.body.title;
  emit(phrase);
  emit("input.body");
});

function lookup(input, reply) {
  emit(input.query.q);
}
router.get("/lookup", lookup);
