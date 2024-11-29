package dev.gustavorh.lms_dev_10.factories.interfaces;

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
import dev.gustavorh.lms_dev_10.services.interfaces.IAuthService;
import dev.gustavorh.lms_dev_10.services.interfaces.IService;
import dev.gustavorh.lms_dev_10.services.interfaces.IUserService;

public interface IServiceFactory {
    IAuthService createAuthService();
    IUserService createUserService();
    IService<Book> createBookService();
    IService<Author> createAuthorService();
    IService<Category> createCategoryService();
    IService<Member> createMemberService();
    IService<Status> createStatusService();
    IService<Role> createRoleService();
    IService<Permission> createPermissionService();
    IService<Loan> createLoanService();
    IService<RolePermissions> createRolePermissionsService();
    IService<RoleUsers> createRoleUsersService();
}
