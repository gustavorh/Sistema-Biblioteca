package dev.gustavorh.lms_dev_10.factories.implementations;

import dev.gustavorh.lms_dev_10.entities.Author;
import dev.gustavorh.lms_dev_10.entities.Book;
import dev.gustavorh.lms_dev_10.entities.Category;
import dev.gustavorh.lms_dev_10.entities.Loan;
import dev.gustavorh.lms_dev_10.entities.Member;
import dev.gustavorh.lms_dev_10.entities.Permission;
import dev.gustavorh.lms_dev_10.entities.Role;
import dev.gustavorh.lms_dev_10.entities.RolePermissions;
import dev.gustavorh.lms_dev_10.entities.RoleUsers;
import dev.gustavorh.lms_dev_10.entities.Status;
import dev.gustavorh.lms_dev_10.factories.interfaces.IRepositoryFactory;
import dev.gustavorh.lms_dev_10.factories.interfaces.IServiceFactory;
import dev.gustavorh.lms_dev_10.services.implementations.AuthService;
import dev.gustavorh.lms_dev_10.services.implementations.AuthorService;
import dev.gustavorh.lms_dev_10.services.implementations.BookService;
import dev.gustavorh.lms_dev_10.services.implementations.CategoryService;
import dev.gustavorh.lms_dev_10.services.implementations.LoanService;
import dev.gustavorh.lms_dev_10.services.implementations.MemberService;
import dev.gustavorh.lms_dev_10.services.implementations.PermissionService;
import dev.gustavorh.lms_dev_10.services.implementations.RolePermissionsService;
import dev.gustavorh.lms_dev_10.services.implementations.RoleService;
import dev.gustavorh.lms_dev_10.services.implementations.RoleUsersService;
import dev.gustavorh.lms_dev_10.services.implementations.StatusService;
import dev.gustavorh.lms_dev_10.services.implementations.UserService;
import dev.gustavorh.lms_dev_10.services.interfaces.IAuthService;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import dev.gustavorh.lms_dev_10.services.interfaces.IUserService;

public class DefaultServiceFactory implements IServiceFactory {
    private final IRepositoryFactory repositoryFactory;

    public DefaultServiceFactory(IRepositoryFactory repositoryFactory) {
        this.repositoryFactory = repositoryFactory;
    }


    @Override
    public IAuthService createAuthService() { return new AuthService(createUserService()); }

    @Override
    public IUserService createUserService() { return new UserService(repositoryFactory.createUserRepository()); }

    @Override
    public IService<Book> createBookService() { return new BookService(repositoryFactory.createBookRepository()); }

    @Override
    public IService<Author> createAuthorService() { return new AuthorService(repositoryFactory.createAuthorRepository()); }

    @Override
    public IService<Category> createCategoryService() { return new CategoryService(repositoryFactory.createCategoryRepository()); }

    @Override
    public IService<Member> createMemberService() { return new MemberService(repositoryFactory.createMemberRepository()); }

    @Override
    public IService<Status> createStatusService() { return new StatusService(repositoryFactory.createStatusRepository()); }

    @Override
    public IService<Role> createRoleService() { return new RoleService(repositoryFactory.createRoleRepository()); }

    @Override
    public IService<Permission> createPermissionService() { return new PermissionService(repositoryFactory.createPermissionRepository()); }

    @Override
    public IService<Loan> createLoanService() { return new LoanService(repositoryFactory.createLoanRepository()); }

    @Override
    public IService<RolePermissions> createRolePermissionsService() { return new RolePermissionsService(repositoryFactory.createRolePermissionsRepository()); }

    @Override
    public IService<RoleUsers> createRoleUsersService() { return new RoleUsersService(repositoryFactory.createRoleUsersRepository()); }
}
