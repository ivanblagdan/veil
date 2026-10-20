//! Source ranges are validated UTF-8 byte ranges, never model or UTF-16 offsets.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Label {
    Ssn,
    CreditCard,
    IpAddress,
    GivenName,
    Surname,
    Email,
    Phone,
    Url,
    TaxId,
    BankAccount,
    RoutingNumber,
    GovernmentId,
    Passport,
    DriversLicense,
    BuildingNumber,
    StreetName,
    SecondaryAddress,
    City,
    State,
    ZipCode,
}
impl Label {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "SSN" => Self::Ssn,
            "CREDIT_CARD" => Self::CreditCard,
            "IP_ADDRESS" => Self::IpAddress,
            "GIVEN_NAME" | "GIVENNAME" => Self::GivenName,
            "SURNAME" | "LASTNAME" => Self::Surname,
            "EMAIL" => Self::Email,
            "PHONE" => Self::Phone,
            "URL" => Self::Url,
            "TAX_ID" => Self::TaxId,
            "BANK_ACCOUNT" => Self::BankAccount,
            "ROUTING_NUMBER" => Self::RoutingNumber,
            "GOVERNMENT_ID" => Self::GovernmentId,
            "PASSPORT" => Self::Passport,
            "DRIVERS_LICENSE" => Self::DriversLicense,
            "BUILDING_NUMBER" => Self::BuildingNumber,
            "STREET_NAME" => Self::StreetName,
            "SECONDARY_ADDRESS" | "SECADDRESS" => Self::SecondaryAddress,
            "CITY" => Self::City,
            "STATE" => Self::State,
            "ZIP_CODE" => Self::ZipCode,
            _ => anyhow::bail!("unrecognized model entity label"),
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssn => "SSN",
            Self::CreditCard => "CREDIT_CARD",
            Self::IpAddress => "IP_ADDRESS",
            Self::GivenName => "GIVEN_NAME",
            Self::Surname => "SURNAME",
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
            Self::Url => "URL",
            Self::TaxId => "TAX_ID",
            Self::BankAccount => "BANK_ACCOUNT",
            Self::RoutingNumber => "ROUTING_NUMBER",
            Self::GovernmentId => "GOVERNMENT_ID",
            Self::Passport => "PASSPORT",
            Self::DriversLicense => "DRIVERS_LICENSE",
            Self::BuildingNumber => "BUILDING_NUMBER",
            Self::StreetName => "STREET_NAME",
            Self::SecondaryAddress => "SECONDARY_ADDRESS",
            Self::City => "CITY",
            Self::State => "STATE",
            Self::ZipCode => "ZIP_CODE",
        }
    }
    pub fn kept(self) -> bool {
        matches!(self, Self::City | Self::State | Self::ZipCode)
    }
    pub fn person(self) -> bool {
        matches!(self, Self::GivenName | Self::Surname)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Source {
    #[serde(rename = "heuristic")]
    Heuristic,
    #[serde(rename = "ner")]
    Model,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRange {
    start: usize,
    end: usize,
}
impl SourceRange {
    pub fn new(text: &str, start: usize, end: usize) -> Result<Self> {
        ensure!(
            start < end
                && end <= text.len()
                && text.is_char_boundary(start)
                && text.is_char_boundary(end),
            "invalid source UTF-8 range"
        );
        Ok(Self { start, end })
    }
    pub fn start(self) -> usize {
        self.start
    }
    pub fn end(self) -> usize {
        self.end
    }
    pub fn text(self, text: &str) -> Result<&str> {
        text.get(self.start..self.end)
            .ok_or_else(|| anyhow::anyhow!("range does not address this source"))
    }
}
#[derive(Clone, Debug)]
pub struct Detection {
    pub range: SourceRange,
    pub label: Label,
    pub score: f32,
    pub source: Source,
}
impl Detection {
    pub fn new(
        text: &str,
        start: usize,
        end: usize,
        label: Label,
        score: f32,
        source: Source,
    ) -> Result<Self> {
        ensure!(
            score.is_finite() && (0.0..=1.0).contains(&score),
            "invalid detection confidence"
        );
        Ok(Self {
            range: SourceRange::new(text, start, end)?,
            label,
            score,
            source,
        })
    }
}
