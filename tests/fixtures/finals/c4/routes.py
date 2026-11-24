from flask import request as incoming
from paperkit.render import emit


@app.route("/entry/<name>")
def entry(name):
    phrase = incoming.args.get("q")
    emit(phrase)
    emit(name)
    phrase = "fixed"
    emit(phrase)
    emit(lookup())


def outside():
    emit("fixed")
