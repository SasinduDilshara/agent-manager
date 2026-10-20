/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import {
  Checkbox,
  InputAdornment,
  ListItemText,
  MenuItem,
  Select,
  Typography,
} from "@wso2/oxygen-ui";
import { Filter } from "@wso2/oxygen-ui-icons-react";

export interface MultiSelectFilterOption {
  value: string;
  /** Records matching the value in the current window, when known. */
  count?: number;
}

interface MultiSelectFilterProps {
  label: string;
  options: MultiSelectFilterOption[];
  selected: string[];
  onChange: (values: string[]) => void;
  disabled?: boolean;
  minWidth?: number;
}

/** A compact multi-value filter: "All <label>" until values are picked. */
export function MultiSelectFilter({
  label,
  options,
  selected,
  onChange,
  disabled,
  minWidth = 150,
}: MultiSelectFilterProps) {
  // A value picked earlier stays listed even when the current window no
  // longer holds it, so it can still be unpicked.
  const values: MultiSelectFilterOption[] = [
    ...options,
    ...selected
      .filter((v) => !options.some((o) => o.value === v))
      .map((value) => ({ value })),
  ];

  return (
    <Select
      size="small"
      variant="outlined"
      multiple
      displayEmpty
      disabled={disabled}
      value={selected}
      onChange={(e) => {
        const next = e.target.value;
        onChange(typeof next === "string" ? next.split(",") : (next as string[]));
      }}
      renderValue={(picked) => {
        const list = picked as string[];
        if (list.length === 0) return `All ${label}`;
        if (list.length === 1) return list[0];
        return `${label}: ${list.length}`;
      }}
      startAdornment={
        <InputAdornment position="start">
          <Filter size={16} />
        </InputAdornment>
      }
      inputProps={{ "aria-label": `Filter by ${label.toLowerCase()}` }}
      sx={{ minWidth, maxWidth: 260 }}
      MenuProps={{ slotProps: { paper: { sx: { maxHeight: 360 } } } }}
    >
      {values.length === 0 && (
        <MenuItem disabled>
          <Typography variant="body2" color="text.secondary">
            No values in this time range
          </Typography>
        </MenuItem>
      )}
      {values.map((option) => (
        <MenuItem key={option.value} value={option.value}>
          <Checkbox checked={selected.includes(option.value)} size="small" />
          <ListItemText
            primary={option.value}
            secondary={
              option.count !== undefined ? `${option.count} records` : undefined
            }
          />
        </MenuItem>
      ))}
    </Select>
  );
}
