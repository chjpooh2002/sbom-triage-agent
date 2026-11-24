from flask import request
from . import paper as local_paper
from .paper import relay, write as put
from .paper import Binder

binder = Binder()


@app.route("/note")
def note():
    return put(request.args.get("q"))


@app.route("/fixed")
def fixed():
    return local_paper.write("fixed")


@app.route("/via")
def indirect():
    return relay("fixed")


@app.route("/other")
def other(put):
    return put("fixed")


@app.route("/bind")
def bind():
    return binder.fold("fixed")
