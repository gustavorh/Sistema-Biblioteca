package dev.gustavorh.lms_dev_10.entities;

public class Inventory {
    private Book book;
    private Integer copiesAvailable;

    public Book getBook() {
        return book;
    }

    public void setBook(Book book) {
        this.book = book;
    }

    public Integer getCopiesAvailable() {
        return copiesAvailable;
    }

    public void setCopiesAvailable(Integer copiesAvailable) {
        this.copiesAvailable = copiesAvailable;
    }
}
