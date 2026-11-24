def write(value):
    return emit(value)


def middle(value):
    return emit(value)


def relay(value):
    return middle(value)


class Binder:
    def fold(self, value):
        return emit(value)
