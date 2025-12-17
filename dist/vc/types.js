// SPDX-FileCopyrightText: 2025 Semiotic AI, Inc.
//
// SPDX-License-Identifier: MIT
export function isWasmVcError(e) {
    if (typeof e !== 'object' || e === null)
        return false;
    const anyE = e;
    return typeof anyE.code === 'string' && typeof anyE.message === 'string';
}
//# sourceMappingURL=types.js.map