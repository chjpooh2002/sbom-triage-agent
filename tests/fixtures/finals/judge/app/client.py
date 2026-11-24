import xmlkit


def fetch(body):
    """원격 문서를 읽는다.

    엔티티 해석 여부는 여기서 정하지 않는다.
    """
    doc = xmlkit.parse_entities(body)
    return doc
