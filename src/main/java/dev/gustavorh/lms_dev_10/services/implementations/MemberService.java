package dev.gustavorh.lms_dev_10.services.implementations;

import dev.gustavorh.lms_dev_10.entities.Member;
import dev.gustavorh.lms_dev_10.exceptions.ServiceException;
import dev.gustavorh.lms_dev_10.repositories.interfaces.IRepository;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import jakarta.persistence.EntityNotFoundException;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

public class MemberService implements IService<Member> {
    private final IRepository<Member> memberRepository;

    public MemberService(IRepository<Member> memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public Optional<Member> findById(Long id) {
        try {
            Optional<Member> memberOptional = memberRepository.findById(id);
            if (memberOptional.isPresent()) {
                return memberOptional;
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving member with id: " + id, e);
        }
    }

    @Override
    public List<Member> findAll() {
        try {
            return memberRepository.findAll();
        } catch (SQLException e) {
            throw new ServiceException("Error retrieving all members", e);
        }
    }

    @Override
    public void save(Member entity) {
        try {
            memberRepository.save(entity);
        } catch (SQLException e) {
            throw new ServiceException("Error saving member", e);
        }
    }

    @Override
    public void update(Member entity) {
        try {
            if (memberRepository.findById(entity.getMemberId()).isPresent()) {
                memberRepository.update(entity);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error updating member", e);
        }
    }

    @Override
    public void delete(Long id) {
        try {
            if (memberRepository.findById(id).isPresent()) {
                memberRepository.delete(id);
            } else {
                throw new EntityNotFoundException("El ID no existe en nuestros registros.");
            }
        } catch (SQLException e) {
            throw new ServiceException("Error deleting member with id: " + id, e);
        }
    }
}
