// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::tickets::{
    create_ticket, get_tickets, modify_ticket, CreateTicketOpts, GetTicketsOpts, ModifyTicketOpts,
};
use gvm_gmp::responses::{CreateTicketResponse, GetTicketsResponse, ModifyTicketResponse};
use gvm_gmp::types::EntityId;

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Tickets ───────────────────────────────────────────────────────────────

    /// Send a `get_tickets` request and return a typed [`GetTicketsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tickets(
        &mut self,
        opts: GetTicketsOpts,
    ) -> Result<GetTicketsResponse, GvmError> {
        let response = self.send(get_tickets(opts)).await?;
        GetTicketsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `create_ticket` request and return a typed [`CreateTicketResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_ticket(
        &mut self,
        result_id: &EntityId,
        opts: CreateTicketOpts,
    ) -> Result<CreateTicketResponse, GvmError> {
        let response = self.send(create_ticket(result_id, opts)).await?;
        CreateTicketResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `modify_ticket` request and return a typed [`ModifyTicketResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_ticket(
        &mut self,
        ticket_id: &EntityId,
        opts: ModifyTicketOpts,
    ) -> Result<ModifyTicketResponse, GvmError> {
        let response = self.send(modify_ticket(ticket_id, opts)).await?;
        ModifyTicketResponse::from_response(&response).map_err(GvmError::Parse)
    }
}
