import lab.paper.Formatter;

class Notes {
    @PostMapping("/entry")
    String entry(
        @RequestParam("text") String text,
        Object unrelated
    ) {
        String label = text;
        emit(label);
        emit(unrelated);
        return "ok";
    }
}
