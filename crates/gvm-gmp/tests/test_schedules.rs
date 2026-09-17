// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::schedules::{
    CloneScheduleRequest, CreateScheduleRequest, DeleteScheduleRequest, GetScheduleRequest,
    GetSchedulesRequest, ModifyScheduleRequest,
};
use gvm_gmp::{GmpRequestCodec, GmpVersion};

const ICALENDAR: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR";

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn create_schedule_with_complete_request() {
    let mut request = CreateScheduleRequest::new("daily-scan", ICALENDAR);
    request.comment = Some("run daily".into());
    request.timezone = Some("UTC".into());

    assert_eq!(
        xml(&request),
        "<create_schedule><name>daily-scan</name><comment>run daily</comment><icalendar>BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR</icalendar><timezone>UTC</timezone></create_schedule>"
    );
}

#[test]
fn schedule_lifecycle_requests_have_exact_xml() {
    assert_eq!(
        xml(&GetSchedulesRequest {
            details: Some(true),
            ..Default::default()
        }),
        "<get_schedules details=\"1\"/>"
    );
    assert_eq!(
        xml(&GetScheduleRequest::new(id("sc1"))),
        "<get_schedules details=\"1\" schedule_id=\"sc1\"/>"
    );
    assert_eq!(
        xml(&CloneScheduleRequest::new(id("sc1"))),
        "<create_schedule><copy>sc1</copy></create_schedule>"
    );

    let mut modify = ModifyScheduleRequest::new(id("sc1"), ICALENDAR);
    modify.name = Some("updated".into());
    modify.timezone = Some("Europe/Berlin".into());
    assert_eq!(
        xml(&modify),
        "<modify_schedule schedule_id=\"sc1\"><name>updated</name><icalendar>BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR</icalendar><timezone>Europe/Berlin</timezone></modify_schedule>"
    );
    assert_eq!(
        xml(&DeleteScheduleRequest::new(id("sc1"), false)),
        "<delete_schedule schedule_id=\"sc1\" ultimate=\"0\"/>"
    );
}
