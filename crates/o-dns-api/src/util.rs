use sqlx::{QueryBuilder, Sqlite};

use super::handlers::Sort;
use crate::handlers::{LatestLogsFilter, ListEntriesFilter};

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

pub fn build_delete_list_entries_query(ids: &[u32]) -> QueryBuilder<'static, Sqlite> {
    let mut query = sqlx::QueryBuilder::new("DELETE FROM allow_deny_list WHERE id IN ");
    query.push_tuples(ids, |mut tup, id| {
        tup.push_bind(*id);
    });
    query.push(" RETURNING *");
    query
}

pub fn build_select_list_entries_with_filters(filter: &ListEntriesFilter) -> QueryBuilder<'static, Sqlite> {
    let mut query = sqlx::QueryBuilder::new("SELECT * FROM allow_deny_list");

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

pub fn build_select_list_entry_by_id(id: u32) -> QueryBuilder<'static, Sqlite> {
    let mut query = sqlx::QueryBuilder::new("SELECT * FROM allow_deny_list WHERE id = ");
    query.push_bind(id);

    query
}

pub fn get_log_count_per_source_query() -> QueryBuilder<'static, Sqlite> {
    sqlx::QueryBuilder::new(
        "SELECT source, COUNT(source) as 'count' FROM query_log WHERE source IS NOT NULL GROUP BY source",
    )
}

pub fn get_failed_requests_count_query() -> QueryBuilder<'static, Sqlite> {
    sqlx::QueryBuilder::new("SELECT COUNT(id) as 'count' FROM query_log WHERE response_code != 0")
}
