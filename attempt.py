class Attempt:
    no_of_a = 0
    def __init__(self, failed):
        Attempt.no_of_a += 1
        self.failed = failed
    def get_total(self):
        return Attempt.no_of_a
