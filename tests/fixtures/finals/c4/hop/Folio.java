package copy.domain;

public class Folio {
    public String write(String text) {
        return emit(text);
    }
    public String write(String text, String title) {
        return emit(title);
    }
    public String label(String text) {
        return emit(text);
    }
    public String label(Integer number) {
        return emit(number);
    }
}
