use php2shell_profiles::Profile;
use serde::Serialize;

pub const COLUMNS: &[&str] = &[
    "PHP",
    "build",
    "zif_system",
    "zval_ptr_dtor",
    "htdata",
    "stage1_n",
    "forge",
    "stage2_t",
    "stage3",
    "RCE",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InventoryRow {
    pub php: String,
    pub build: String,
    pub zif_system: String,
    pub zval_ptr_dtor: String,
    pub htdata: String,
    pub stage1_n: String,
    pub forge: String,
    pub stage2_t: String,
    pub stage3: String,
    pub rce: String,
    pub status: String,
    pub file: String,
}

impl InventoryRow {
    fn from_profile(profile: &Profile) -> Self {
        let libphp = profile.object("libphp");
        let stages = profile.object("stages");
        let get = |map: Option<&serde_json::Map<String, serde_json::Value>>, key: &str| {
            map.and_then(|m| m.get(key))
                .map(|value| match value {
                    serde_json::Value::Null => "-".to_owned(),
                    serde_json::Value::String(text) => text.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_else(|| "-".to_owned())
        };
        Self {
            php: profile.string("php_version").unwrap_or("-").to_owned(),
            // Upstream `php2shell_inventory.py` uses the full profile name.
            build: profile.string("name").unwrap_or("-").to_owned(),
            zif_system: get(libphp, "zif_system"),
            zval_ptr_dtor: get(libphp, "zval_ptr_dtor"),
            htdata: get(libphp, "htdata"),
            stage1_n: get(stages, "stage1_n"),
            forge: get(stages, "stage1_forge_len"),
            stage2_t: get(stages, "stage2_t"),
            stage3: get(stages, "stage3_mode"),
            rce: if profile.rce() { "yes" } else { "no" }.to_owned(),
            status: profile.status().to_owned(),
            file: profile.source.to_string_lossy().into_owned(),
        }
    }

    fn values(&self) -> Vec<&str> {
        vec![
            &self.php,
            &self.build,
            &self.zif_system,
            &self.zval_ptr_dtor,
            &self.htdata,
            &self.stage1_n,
            &self.forge,
            &self.stage2_t,
            &self.stage3,
            &self.rce,
        ]
    }
}

pub fn rows<'a>(profiles: impl IntoIterator<Item = &'a Profile>) -> Vec<InventoryRow> {
    let mut rows: Vec<InventoryRow> = profiles
        .into_iter()
        .map(InventoryRow::from_profile)
        .collect();
    rows.sort_by(|a, b| {
        let key = |value: &str| -> Vec<u64> {
            value
                .split('.')
                .map(|part| part.parse::<u64>().unwrap_or(0))
                .collect()
        };
        key(&a.php)
            .cmp(&key(&b.php))
            .then_with(|| a.file.cmp(&b.file))
    });
    rows
}

pub fn render_table(rows: &[InventoryRow]) -> String {
    if rows.is_empty() {
        return "no profiles match the current filter".to_owned();
    }
    let mut widths: Vec<usize> = COLUMNS.iter().map(|column| column.len()).collect();
    for row in rows {
        for (index, value) in row.values().iter().enumerate() {
            widths[index] = widths[index].max(value.chars().count());
        }
    }
    let mut out = String::new();
    out.push_str(
        &COLUMNS
            .iter()
            .zip(&widths)
            .map(|(column, width)| format!("{column:<width$}"))
            .collect::<Vec<_>>()
            .join("  "),
    );
    out.push('\n');
    out.push_str(
        &widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>()
            .join("  "),
    );
    out.push('\n');
    for row in rows {
        out.push_str(
            &row.values()
                .iter()
                .zip(&widths)
                .map(|(value, width)| format!("{value:<width$}"))
                .collect::<Vec<_>>()
                .join("  "),
        );
        out.push('\n');
    }
    let verified = rows.iter().filter(|row| row.rce == "yes").count();
    out.push_str(&format!(
        "\n{} profiles, {} with verified RCE",
        rows.len(),
        verified
    ));
    out
}

pub fn render_json(rows: &[InventoryRow]) -> String {
    serde_json::to_string_pretty(rows).unwrap_or_else(|_| "[]".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile() -> Profile {
        Profile::new(
            json!({
                "name": "php-8.4.26-bookworm-amd64",
                "php_version": "8.4.26",
                "branch": "8.4",
                "distro": "bookworm",
                "sapi": "apache2handler",
                "arch": "amd64",
                "rce": true,
                "status": "verified",
                "libphp": { "zif_system": "0x465370", "zval_ptr_dtor": "0x65eb60", "htdata": "0x690d8" },
                "stages": { "stage1_n": 841, "stage1_forge_len": 79, "stage2_t": 406, "stage3_mode": "carrier" }
            }),
            "profiles/8.4.26-bookworm-amd64.json",
        )
    }

    #[test]
    fn renders_the_upstream_column_set() {
        let profile = profile();
        let rows = rows([&profile]);
        assert_eq!(rows[0].php, "8.4.26");
        assert_eq!(rows[0].rce, "yes");
        let table = render_table(&rows);
        assert!(table.lines().next().unwrap().starts_with("PHP"));
        assert!(table.contains("8.4.26"));
        assert!(table.contains("1 profiles, 1 with verified RCE"));
    }

    #[test]
    fn json_contains_status_and_file() {
        let profile = profile();
        let rows = rows([&profile]);
        let json = render_json(&rows);
        assert!(json.contains("\"status\": \"verified\""));
        assert!(json.contains("\"file\""));
    }
}
