#ifndef BITS_H
#define BITS_H

// Value with bit _n_ set
#define BIT(_n_) (1 << _n_)

// Value with the least significant _width_ bits set
#define BIT_MASK(_width_) (BIT(_width_) - 1)

// Value with _width_ bits set starting at bit _offset_
#define BF_MASK(_offset_, _width_) (BIT_MASK(_width_) << _offset_)

// Clears a bitfield from _value_
#define BF_CLEAR(_value_, _offset_, _width_) (_value_ & (~BF_MASK(_offset_, _width_)))

// Extracts a bitfield from a value
#define BF_GET(_value_, _offset_, _width_) ((_value_ >> _offset_) & BIT_MASK(_width_))

// Compose a value with the given bitfield set to _bfValue_
#define BF_DEFINE(_bfValue_, _offset_, _width_) ((_bfValue_ & BIT_MASK(_width_)) << _offset_)

// Replace the given bitfield with the value in _bfValue_
#define BF_SET(_value_, _bfValue_, _offset_, _width_) ( \
        BF_CLEAR(_value_, _offset_, _width_) |          \
        BF_DEFINE(_bfValue_, _offset_, _width_)         \
        )

#endif // BITS_H
