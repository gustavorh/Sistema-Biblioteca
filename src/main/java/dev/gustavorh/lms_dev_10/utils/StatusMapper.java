package dev.gustavorh.lms_dev_10.utils;

import dev.gustavorh.lms_dev_10.entities.Status;

import java.sql.ResultSet;
import java.sql.SQLException;

public class StatusMapper implements IRowMapper<Status> {
    @Override
    public Status mapRow(ResultSet rs) throws SQLException {
        Status status = new Status();
        status.setStatusId(rs.getLong("id_estado"));
        status.setName(rs.getString("nombre"));
        status.setDescription(rs.getString("descripcion"));

        return status;
    }
}
