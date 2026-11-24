package copy.web;
import copy.domain.Folio;

class Pages {
    private Folio book;

    @PostMapping("/entry")
    String entry(@RequestParam String text) {
        return book.write(text);
    }

    @GetMapping("/literal")
    String literal() {
        return this.book.write("a", "b");
    }

    @GetMapping("/ambiguous")
    String ambiguous(@RequestParam String text) {
        return book.label(text);
    }

    @GetMapping("/shadow")
    String shadow(Other book) {
        return book.write("text");
    }
}
