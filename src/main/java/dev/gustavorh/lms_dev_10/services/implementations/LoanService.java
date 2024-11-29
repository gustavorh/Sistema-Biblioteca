package dev.gustavorh.lms_dev_10.services.implementations;

import dev.gustavorh.lms_dev_10.entities.Loan;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import jakarta.persistence.EntityNotFoundException;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

public class LoanService implements IService<Loan> {
    private final IRepository<Loan> loanRepository;

    public LoanService(IRepository<Loan> loanRepository) {
        this.loanRepository = loanRepository;
    }

    @Override
    public Optional<Loan> findById(Long id) {
        try {
            Optional<Loan> loanOptional = loanRepository.findById(id);
            if (loanOptional.isPresent()) {
                return loanOptional;
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving loan with id: " + id, e);
        }
    }

    @Override
    public List<Loan> findAll() {
        try {
            return loanRepository.findAll();
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving all loans", e);
        }
    }

    @Override
    public void save(Loan entity) {
        try {
            loanRepository.save(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error saving loan", e);
        }
    }

    @Override
    public void update(Loan entity) {
        try {
            if (loanRepository.findById(entity.getLoanId()).isPresent()) {
                loanRepository.update(entity);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error updating loan", e);
        }
    }

    @Override
    public void delete(Long id) {
        try {
            if (loanRepository.findById(id).isPresent()) {
                loanRepository.delete(id);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error deleting loan with id: " + id, e);
        }
    }
}
