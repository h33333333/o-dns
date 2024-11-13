use sqlx::{QueryBuilder, Sqlite};

use super::handlers::{LatestLogsFilter, Sort};

pub fn build_select_logs_query_with_filters(filter: &LatestLogsFilter) -> QueryBuilder<'static, Sqlite> {
    let mut query = sqlx::QueryBuilder::new("SELECT * FROM query_log");

    if let Some(from_timestamp) = filter.from_timestamp {
        query.push(" WHERE timestamp >=").push_bind(from_timestamp);
    }

    query.push(" ORDER BY id");
    if let Sort::Desc = filter.sort {
        query.push(" DESC");
    }

    if let Some(limit) = filter.limit {
        query.push(" LIMIT").push_bind(limit);
        if let Some(offest) = filter.offset {
            query.push(" OFFSET").push_bind(offest);
        }
    }

    query
}

pub fn build_delete_list_entry_query(id: u32) -> QueryBuilder<'static, Sqlite> {
    let mut query = sqlx::QueryBuilder::new("DELETE FROM allow_deny_list WHERE id = ");
    query.push_bind(id);
    query.push(" RETURNING *");
    query
}
