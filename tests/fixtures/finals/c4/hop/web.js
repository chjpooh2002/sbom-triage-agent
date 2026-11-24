import {write as insert, defer} from "./edition.js";
const shelf = require("./shelf");
router.post("/edition", req => insert(req.body.text));
router.post("/shelf", req => shelf.write(req.body.text));
router.get("/later", req => defer(req.query.text));
router.get("/queue", req => queue(() => shelf.write(req.query.text)));
router.post("/fold", req => shelf.fold(req.body.text));
router.get("/shadow", shelf => shelf.write("fixed"));
