import xmlkit


def test_parse():
    xmlkit.parse_entities(b"<a/>")
