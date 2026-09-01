"""
A plain file with no cryptographic content at all.
Used to confirm the scanner does NOT produce false positives on unrelated code.
"""


def add_numbers(a: int, b: int) -> int:
    return a + b


def greet(name: str) -> str:
    return f"Hello, {name}!"


class ShoppingCart:
    def __init__(self):
        self.items: list[str] = []

    def add_item(self, item: str) -> None:
        self.items.append(item)

    def total_items(self) -> int:
        return len(self.items)
