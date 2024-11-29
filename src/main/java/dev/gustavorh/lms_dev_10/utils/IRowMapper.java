package dev.gustavorh.lms_dev_10.utils;

import java.sql.ResultSet;
import java.sql.SQLException;

public interface IRowMapper<T> {
    T mapRow(ResultSet rs) throws SQLException;
}
