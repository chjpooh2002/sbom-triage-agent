class Raw {
    @GetMapping
    String read(HttpServletRequest input) {
        return emit(input.getParameter("name"));
    }
}
