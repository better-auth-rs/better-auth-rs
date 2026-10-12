"use strict";
/**
 * Adapted from https://github.com/mysqljs/sqlstring/blob/cd528556b4b6bcf300c3db515026935dedf7cfa1/lib/SqlString.js
 * MIT LICENSE: https://github.com/mysqljs/sqlstring/blob/cd528556b4b6bcf300c3db515026935dedf7cfa1/LICENSE
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.raw = exports.format = exports.escape = exports.arrayToList = exports.bufferToString = exports.objectToValues = exports.escapeId = exports.temporalToString = exports.dateToString = void 0;
const buffer_1 = require("buffer");
const CONTEXT_TRIGGER = new Uint8Array(128);
const SET_CLAUSE_TERMINATORS_BY_FIRST = {};
const SET_CLAUSE_TERMINATORS = [
    'where',
    'order',
    'group',
    'having',
    'limit',
    'union',
    'returning',
    'into',
    'for',
    'lock',
    'offset',
    'window',
    'procedure',
    'on',
];
const regex = {
    backtick: /`/g,
    dot: /\./g,
    timezone: /([+\-\s])(\d\d):?(\d\d)?/,
    escapeChars: /[\0\b\t\n\r\x1a"'\\]/g,
};
const charCode = {
    singleQuote: 39,
    backtick: 96,
    backslash: 92,
    dash: 45,
    slash: 47,
    asterisk: 42,
    exclamation: 33,
    plus: 43,
    questionMark: 63,
    comma: 44,
    openParen: 40,
    closeParen: 41,
    semicolon: 59,
    newline: 10,
    space: 32,
    tab: 9,
    carriageReturn: 13,
};
// Chars that open a string, identifier, or comment
CONTEXT_TRIGGER[charCode.singleQuote] = 1;
CONTEXT_TRIGGER[charCode.backtick] = 1;
CONTEXT_TRIGGER[charCode.dash] = 1;
CONTEXT_TRIGGER[charCode.slash] = 1;
// Bucket terminators by their first character
for (const word of SET_CLAUSE_TERMINATORS) {
    const first = word.charCodeAt(0);
    const bucket = SET_CLAUSE_TERMINATORS_BY_FIRST[first];
    if (bucket)
        bucket.push(word);
    else
        SET_CLAUSE_TERMINATORS_BY_FIRST[first] = [word];
}
const hasOwnProperty = Object.prototype.hasOwnProperty;
const isRecord = (value) => typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    !(value instanceof Set) &&
    !(value instanceof Map);
const isWordChar = (code) => (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) ||
    code === 95;
const isWhitespace = (code) => code === charCode.space ||
    code === charCode.tab ||
    code === charCode.newline ||
    code === charCode.carriageReturn;
const toLower = (code) => code | 32;
const matchesWord = (sql, position, word, length) => {
    const wordLength = word.length;
    for (let offset = 0; offset < wordLength; offset++)
        if (toLower(sql.charCodeAt(position + offset)) !== word.charCodeAt(offset))
            return false;
    return ((position === 0 || !isWordChar(sql.charCodeAt(position - 1))) &&
        (position + wordLength >= length ||
            !isWordChar(sql.charCodeAt(position + wordLength))));
};
const skipSqlContext = (sql, position) => {
    const currentChar = sql.charCodeAt(position);
    const nextChar = sql.charCodeAt(position + 1);
    if (currentChar === charCode.singleQuote) {
        for (let cursor = position + 1; cursor < sql.length; cursor++) {
            if (sql.charCodeAt(cursor) === charCode.backslash)
                cursor++;
            else if (sql.charCodeAt(cursor) === charCode.singleQuote)
                return cursor + 1;
        }
        return sql.length;
    }
    if (currentChar === charCode.backtick) {
        const length = sql.length;
        for (let cursor = position + 1; cursor < length; cursor++) {
            if (sql.charCodeAt(cursor) !== charCode.backtick)
                continue;
            if (sql.charCodeAt(cursor + 1) === charCode.backtick) {
                cursor++;
                continue;
            }
            return cursor + 1;
        }
        return length;
    }
    if (currentChar === charCode.dash && nextChar === charCode.dash) {
        const afterDash = sql.charCodeAt(position + 2);
        if (Number.isNaN(afterDash) || afterDash <= charCode.space) {
            const lineBreak = sql.indexOf('\n', position + 2);
            return lineBreak === -1 ? sql.length : lineBreak + 1;
        }
        return -1;
    }
    if (currentChar === charCode.slash && nextChar === charCode.asterisk) {
        const markerChar = sql.charCodeAt(position + 2);
        if (markerChar === charCode.exclamation || markerChar === charCode.plus)
            return -1;
        const commentEnd = sql.indexOf('*/', position + 2);
        return commentEnd === -1 ? sql.length : commentEnd + 2;
    }
    return -1;
};
const findNextPlaceholder = (sql, start) => {
    const sqlLength = sql.length;
    for (let position = start; position < sqlLength; position++) {
        const code = sql.charCodeAt(position);
        if (code === charCode.questionMark)
            return position;
        if (code < 128 && CONTEXT_TRIGGER[code]) {
            const contextEnd = skipSqlContext(sql, position);
            if (contextEnd !== -1)
                position = contextEnd - 1;
        }
    }
    return -1;
};
const isInSetAssignmentList = (sql, setEnd, placeholderPosition) => {
    const length = sql.length;
    let depth = 0;
    let sawContent = false;
    let lastWasComma = false;
    for (let i = setEnd; i < placeholderPosition;) {
        const code = sql.charCodeAt(i);
        if (code < 128 && CONTEXT_TRIGGER[code]) {
            const contextEnd = skipSqlContext(sql, i);
            if (contextEnd !== -1) {
                i = contextEnd;
                sawContent = true;
                lastWasComma = false;
                continue;
            }
        }
        if (isWhitespace(code)) {
            i++;
            continue;
        }
        if (code === charCode.openParen) {
            depth++;
            sawContent = true;
            lastWasComma = false;
            i++;
            continue;
        }
        if (code === charCode.closeParen) {
            if (--depth < 0)
                return false;
            sawContent = true;
            lastWasComma = false;
            i++;
            continue;
        }
        if (isWordChar(code)) {
            if (depth === 0 && !(code >= 48 && code <= 57)) {
                const bucket = SET_CLAUSE_TERMINATORS_BY_FIRST[code | 32];
                if (bucket)
                    for (let t = 0; t < bucket.length; t++)
                        if (matchesWord(sql, i, bucket[t], length))
                            return false;
            }
            do {
                i++;
            } while (i < placeholderPosition && isWordChar(sql.charCodeAt(i)));
            sawContent = true;
            lastWasComma = false;
            continue;
        }
        if (depth === 0) {
            if (code === charCode.semicolon)
                return false;
            if (code === charCode.comma) {
                lastWasComma = true;
                sawContent = true;
                i++;
                continue;
            }
        }
        sawContent = true;
        lastWasComma = false;
        i++;
    }
    return depth === 0 && (!sawContent || lastWasComma);
};
const findSetKeyword = (sql, startFrom = 0) => {
    const length = sql.length;
    for (let position = startFrom; position < length; position++) {
        const code = sql.charCodeAt(position);
        if (code < 128 && CONTEXT_TRIGGER[code]) {
            const contextEnd = skipSqlContext(sql, position);
            if (contextEnd !== -1) {
                position = contextEnd - 1;
                continue;
            }
        }
        const lower = code | 32;
        if (lower === 115 && matchesWord(sql, position, 'set', length))
            return position + 3;
        if (lower === 107 && matchesWord(sql, position, 'key', length)) {
            let cursor = position + 3;
            while (cursor < length && isWhitespace(sql.charCodeAt(cursor)))
                cursor++;
            if (matchesWord(sql, cursor, 'update', length))
                return cursor + 6;
        }
    }
    return -1;
};
const isDate = (value) => Object.prototype.toString.call(value) === '[object Date]';
const isTemporal = (value) => Object.prototype.toString.call(value).startsWith('[object Temporal.');
const hasSqlString = (value) => typeof value === 'object' &&
    value !== null &&
    'toSqlString' in value &&
    typeof value.toSqlString === 'function';
const escapeString = (value) => {
    const escapeChars = regex.escapeChars;
    escapeChars.lastIndex = 0;
    const first = escapeChars.exec(value);
    if (first === null)
        return `'${value}'`;
    const length = value.length;
    let result = "'" + value.slice(0, first.index);
    let chunkStart = first.index;
    for (let i = first.index; i < length; i++) {
        let escaped;
        switch (value.charCodeAt(i)) {
            case 0:
                escaped = '\\0';
                break;
            case 8:
                escaped = '\\b';
                break;
            case 9:
                escaped = '\\t';
                break;
            case 10:
                escaped = '\\n';
                break;
            case 13:
                escaped = '\\r';
                break;
            case 26:
                escaped = '\\Z';
                break;
            case 34:
                escaped = '\\"';
                break;
            case 39:
                escaped = "\\'";
                break;
            case 92:
                escaped = '\\\\';
                break;
            default:
                continue;
        }
        result += value.slice(chunkStart, i) + escaped;
        chunkStart = i + 1;
    }
    return result + value.slice(chunkStart) + "'";
};
const pad2 = (value) => (value < 10 ? '0' + value : '' + value);
const pad3 = (value) => value < 10 ? '00' + value : value < 100 ? '0' + value : '' + value;
const pad4 = (value) => value < 10
    ? '000' + value
    : value < 100
        ? '00' + value
        : value < 1000
            ? '0' + value
            : '' + value;
const convertTimezone = (tz) => {
    if (tz === 'Z')
        return 0;
    const timezoneMatch = tz.match(regex.timezone);
    if (timezoneMatch)
        return ((timezoneMatch[1] === '-' ? -1 : 1) *
            (Number.parseInt(timezoneMatch[2], 10) +
                (timezoneMatch[3] ? Number.parseInt(timezoneMatch[3], 10) : 0) / 60) *
            60);
    return false;
};
const dateToString = (date, timezone) => {
    if (Number.isNaN(date.getTime()))
        return 'NULL';
    let year;
    let month;
    let day;
    let hour;
    let minute;
    let second;
    let millisecond;
    if (timezone === 'local') {
        year = date.getFullYear();
        month = date.getMonth() + 1;
        day = date.getDate();
        hour = date.getHours();
        minute = date.getMinutes();
        second = date.getSeconds();
        millisecond = date.getMilliseconds();
    }
    else {
        const timezoneOffsetMinutes = convertTimezone(timezone);
        let time = date.getTime();
        if (timezoneOffsetMinutes !== false && timezoneOffsetMinutes !== 0)
            time += timezoneOffsetMinutes * 60000;
        const adjustedDate = new Date(time);
        year = adjustedDate.getUTCFullYear();
        month = adjustedDate.getUTCMonth() + 1;
        day = adjustedDate.getUTCDate();
        hour = adjustedDate.getUTCHours();
        minute = adjustedDate.getUTCMinutes();
        second = adjustedDate.getUTCSeconds();
        millisecond = adjustedDate.getUTCMilliseconds();
    }
    // YYYY-MM-DD HH:mm:ss.mmm
    return escapeString(pad4(year) +
        '-' +
        pad2(month) +
        '-' +
        pad2(day) +
        ' ' +
        pad2(hour) +
        ':' +
        pad2(minute) +
        ':' +
        pad2(second) +
        '.' +
        pad3(millisecond));
};
exports.dateToString = dateToString;
const temporalToString = (value, timezone) => {
    if (typeof value.epochMilliseconds === 'number')
        return (0, exports.dateToString)(new Date(value.epochMilliseconds), timezone || 'local');
    if (value[Symbol.toStringTag] === 'Temporal.PlainDateTime')
        return escapeString(value.toString().replace('T', ' '));
    return escapeString(value.toString());
};
exports.temporalToString = temporalToString;
const escapeId = (value, forbidQualified) => {
    if (Array.isArray(value)) {
        const length = value.length;
        let sql = '';
        for (let i = 0; i < length; i++) {
            if (i > 0)
                sql += ', ';
            sql += (0, exports.escapeId)(value[i], forbidQualified);
        }
        return sql;
    }
    const identifier = String(value);
    const hasJsonOperator = !forbidQualified && identifier.indexOf('->') !== -1;
    if (forbidQualified || hasJsonOperator) {
        if (identifier.indexOf('`') === -1)
            return `\`${identifier}\``;
        return `\`${identifier.replace(regex.backtick, '``')}\``;
    }
    if (identifier.indexOf('`') === -1 && identifier.indexOf('.') === -1)
        return `\`${identifier}\``;
    return `\`${identifier
        .replace(regex.backtick, '``')
        .replace(regex.dot, '`.`')}\``;
};
exports.escapeId = escapeId;
const objectToValues = (object, timezone) => {
    let sql = '';
    if (object instanceof Map) {
        for (const [key, value] of object) {
            if (typeof value === 'function')
                continue;
            if (sql.length > 0)
                sql += ', ';
            sql += (0, exports.escapeId)(String(key));
            sql += ' = ';
            sql += (0, exports.escape)(value, true, timezone);
        }
        return sql;
    }
    for (const key in object) {
        if (!hasOwnProperty.call(object, key))
            continue;
        const value = object[key];
        if (typeof value === 'function')
            continue;
        if (sql.length > 0)
            sql += ', ';
        sql += (0, exports.escapeId)(key);
        sql += ' = ';
        sql += (0, exports.escape)(value, true, timezone);
    }
    return sql;
};
exports.objectToValues = objectToValues;
const bufferToString = (buffer) => `X${escapeString(buffer.toString('hex'))}`;
exports.bufferToString = bufferToString;
const arrayToList = (array, timezone) => {
    const length = array.length;
    let sql = '';
    for (let i = 0; i < length; i++) {
        if (i > 0)
            sql += ', ';
        const value = array[i];
        if (Array.isArray(value))
            sql += `(${(0, exports.arrayToList)(value, timezone)})`;
        else if (value instanceof Set)
            sql += `(${(0, exports.arrayToList)(Array.from(value), timezone)})`;
        else
            sql += (0, exports.escape)(value, true, timezone);
    }
    return sql;
};
exports.arrayToList = arrayToList;
const escape = (value, stringifyObjects, timezone) => {
    if (value === undefined || value === null)
        return 'NULL';
    switch (typeof value) {
        case 'boolean':
            return value ? 'true' : 'false';
        case 'number':
        case 'bigint':
            return value + '';
        case 'object': {
            if (isDate(value))
                return (0, exports.dateToString)(value, timezone || 'local');
            if (isTemporal(value))
                return (0, exports.temporalToString)(value, timezone);
            if (Array.isArray(value))
                return (0, exports.arrayToList)(value, timezone);
            if (value instanceof Set)
                return (0, exports.arrayToList)(Array.from(value), timezone);
            if (buffer_1.Buffer.isBuffer(value))
                return (0, exports.bufferToString)(value);
            if (value instanceof Uint8Array)
                return (0, exports.bufferToString)(buffer_1.Buffer.from(value));
            if (hasSqlString(value))
                return String(value.toSqlString());
            if (!(stringifyObjects === undefined || stringifyObjects === null))
                return escapeString(String(value));
            if (isRecord(value) || value instanceof Map)
                return (0, exports.objectToValues)(value, timezone);
            return escapeString(String(value));
        }
        case 'string':
            return escapeString(value);
        default:
            return escapeString(String(value));
    }
};
exports.escape = escape;
const format = (sql, values, stringifyObjects, timezone) => {
    if (values === undefined || values === null)
        return sql;
    const valuesArray = Array.isArray(values) ? values : [values];
    const length = valuesArray.length;
    let setIndex = -2; // -2 = not yet computed, -1 = no SET found
    let nextSetIndex = -1; // -1 = no SET after setIndex
    let result = '';
    let chunkIndex = 0;
    let valuesIndex = 0;
    let placeholderPosition = findNextPlaceholder(sql, 0);
    while (valuesIndex < length && placeholderPosition !== -1) {
        // Count consecutive question marks to detect ? vs ?? vs ???+
        let placeholderEnd = placeholderPosition + 1;
        let escapedValue;
        while (sql.charCodeAt(placeholderEnd) === 63)
            placeholderEnd++;
        const placeholderLength = placeholderEnd - placeholderPosition;
        const currentValue = valuesArray[valuesIndex];
        if (placeholderLength > 2) {
            placeholderPosition = findNextPlaceholder(sql, placeholderEnd);
            continue;
        }
        if (placeholderLength === 2)
            escapedValue = (0, exports.escapeId)(currentValue);
        else if (typeof currentValue === 'number' ||
            typeof currentValue === 'bigint')
            escapedValue = `${currentValue}`;
        else if (typeof currentValue === 'object' &&
            currentValue !== null &&
            !stringifyObjects) {
            const expandable = !(Array.isArray(currentValue) ||
                currentValue instanceof Uint8Array ||
                currentValue instanceof Date ||
                hasSqlString(currentValue) ||
                isDate(currentValue)) &&
                (isRecord(currentValue) || currentValue instanceof Map);
            if (expandable) {
                // A SET assignment follows the keyword (a letter) or a comma continuing the list
                let previous = placeholderPosition - 1;
                while (previous >= chunkIndex && isWhitespace(sql.charCodeAt(previous)))
                    previous--;
                const previousChar = previous >= chunkIndex ? toLower(sql.charCodeAt(previous)) : 0;
                if ((previousChar < 97 || previousChar > 122) &&
                    previousChar !== charCode.comma)
                    escapedValue = (0, exports.escape)(currentValue, true, timezone);
                else {
                    // Lazy: resolve the first SET and its successor once
                    if (setIndex === -2) {
                        setIndex = findSetKeyword(sql);
                        nextSetIndex = setIndex === -1 ? -1 : findSetKeyword(sql, setIndex);
                    }
                    // Nearest: advance to the SET closest before this placeholder
                    while (nextSetIndex !== -1 && nextSetIndex <= placeholderPosition) {
                        setIndex = nextSetIndex;
                        nextSetIndex = findSetKeyword(sql, nextSetIndex);
                    }
                    if (setIndex !== -1 &&
                        setIndex <= placeholderPosition &&
                        isInSetAssignmentList(sql, setIndex, placeholderPosition))
                        escapedValue = (0, exports.objectToValues)(currentValue, timezone);
                    else
                        escapedValue = (0, exports.escape)(currentValue, true, timezone);
                }
            }
            else
                escapedValue = (0, exports.escape)(currentValue, true, timezone);
        }
        else
            escapedValue = (0, exports.escape)(currentValue, stringifyObjects, timezone);
        result += sql.slice(chunkIndex, placeholderPosition);
        result += escapedValue;
        chunkIndex = placeholderEnd;
        valuesIndex++;
        placeholderPosition = findNextPlaceholder(sql, placeholderEnd);
    }
    if (chunkIndex === 0)
        return sql;
    if (chunkIndex < sql.length)
        return result + sql.slice(chunkIndex);
    return result;
};
exports.format = format;
const raw = (sql) => {
    if (typeof sql !== 'string')
        throw new TypeError('argument sql must be a string');
    return {
        toSqlString: () => sql,
    };
};
exports.raw = raw;
