package dev.gustavorh.lms_dev_10.utils;

import dev.gustavorh.lms_dev_10.entities.Category;

import java.sql.ResultSet;
import java.sql.SQLException;

public class CategoryMapper implements IRowMapper<Category> {
    @Override
    public Category mapRow(ResultSet rs) throws SQLException {
        Category category = new Category();
        category.setCategoryId(rs.getLong("id_categoria"));
        category.setName(rs.getString("nombre"));
        return category;
    }
}
