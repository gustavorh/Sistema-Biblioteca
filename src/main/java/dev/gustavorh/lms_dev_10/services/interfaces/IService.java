package dev.gustavorh.lms_dev_10.services.interfaces;

import java.util.List;
import java.util.Optional;

// Generic Service interfaces
public interface IService<T> {
    Optional<T> findById(Long id);
    List<T> findAll();
    void save(T entity);
    void update(T entity);
    void delete(Long id);
}
