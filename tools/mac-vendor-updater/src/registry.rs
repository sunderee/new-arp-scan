//! IEEE Registration Authority public listings converted by this updater.

/// One IEEE MAC registry fetched and folded into `ieee-oui.txt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IeeeMacRegistry {
    /// MAC Address Block Large (OUI / 24-bit / 6 hex digits).
    MaL,
    /// MAC Address Block Medium (28-bit / 7 hex digits).
    MaM,
    /// MAC Address Block Small (OUI-36 / 36-bit / 9 hex digits).
    MaS,
    /// Individual Address Block (legacy 36-bit / 9 hex digits).
    Iab,
}

impl IeeeMacRegistry {
    /// Registries emitted into `ieee-oui.txt`, in file order.
    pub const ALL: [Self; 4] = [Self::MaL, Self::MaM, Self::MaS, Self::Iab];

    /// Official IEEE CSV URL for this registry.
    #[must_use]
    pub const fn csv_url(self) -> &'static str {
        match self {
            Self::MaL => "https://standards-oui.ieee.org/oui/oui.csv",
            Self::MaM => "https://standards-oui.ieee.org/oui28/mam.csv",
            Self::MaS => "https://standards-oui.ieee.org/oui36/oui36.csv",
            Self::Iab => "https://standards-oui.ieee.org/iab/iab.csv",
        }
    }

    /// `Registry` column value in the official CSV.
    #[must_use]
    pub const fn csv_registry_label(self) -> &'static str {
        match self {
            Self::MaL => "MA-L",
            Self::MaM => "MA-M",
            Self::MaS => "MA-S",
            Self::Iab => "IAB",
        }
    }

    /// Hexadecimal digit count of `Assignment` after stripping IEEE separators.
    #[must_use]
    pub const fn assignment_hex_digit_count(self) -> usize {
        match self {
            Self::MaL => 6,
            Self::MaM => 7,
            Self::MaS | Self::Iab => 9,
        }
    }

    /// Local file name used with `--from-dir` (and as the curl output name).
    #[must_use]
    pub const fn csv_file_name(self) -> &'static str {
        match self {
            Self::MaL => "oui.csv",
            Self::MaM => "mam.csv",
            Self::MaS => "oui36.csv",
            Self::Iab => "iab.csv",
        }
    }
}

impl std::fmt::Display for IeeeMacRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.csv_registry_label())
    }
}

#[cfg(test)]
mod tests {
    use super::IeeeMacRegistry;

    #[test]
    fn assignment_widths_match_ieee_block_sizes() {
        // Arrange
        // Act
        // Assert
        assert_eq!(IeeeMacRegistry::MaL.assignment_hex_digit_count(), 6);
        assert_eq!(IeeeMacRegistry::MaM.assignment_hex_digit_count(), 7);
        assert_eq!(IeeeMacRegistry::MaS.assignment_hex_digit_count(), 9);
        assert_eq!(IeeeMacRegistry::Iab.assignment_hex_digit_count(), 9);
        assert_eq!(IeeeMacRegistry::MaL.to_string(), "MA-L");
        assert_eq!(IeeeMacRegistry::Iab.to_string(), "IAB");
    }

    #[test]
    fn all_registries_are_listed_in_output_order() {
        // Arrange
        // Act
        let labels: Vec<&str> = IeeeMacRegistry::ALL
            .iter()
            .map(|registry| registry.csv_registry_label())
            .collect();

        // Assert
        assert_eq!(labels, ["MA-L", "MA-M", "MA-S", "IAB"]);
    }

    #[test]
    fn official_csv_urls_are_https_ieee_listings() {
        // Arrange
        // Act
        let urls: Vec<&str> = IeeeMacRegistry::ALL
            .iter()
            .map(|registry| registry.csv_url())
            .collect();

        // Assert
        assert_eq!(
            urls,
            [
                "https://standards-oui.ieee.org/oui/oui.csv",
                "https://standards-oui.ieee.org/oui28/mam.csv",
                "https://standards-oui.ieee.org/oui36/oui36.csv",
                "https://standards-oui.ieee.org/iab/iab.csv",
            ]
        );
        assert_eq!(
            IeeeMacRegistry::ALL
                .iter()
                .map(|registry| registry.csv_file_name())
                .collect::<Vec<_>>(),
            ["oui.csv", "mam.csv", "oui36.csv", "iab.csv"]
        );
    }
}
