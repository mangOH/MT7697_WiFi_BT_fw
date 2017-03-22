#ifndef SPI_SLAVE_QUEUES_H
#define SPI_SLAVE_QUEUES_H

#include <stdint.h>

void spi_queue_init(void);
size_t spi_queue_read(uint8_t channel, uint32_t* buffer, size_t num_words);
size_t spi_queue_read(uint8_t channel, uint32_t* buffer, size_t num_words);
size_t spi_queue_write(uint8_t channel, const uint32_t* buffer, size_t num_words);
size_t spi_queue_get_capacity_in_words(uint8_t channel);
size_t spi_queue_get_num_words_used(uint8_t channel);
size_t spi_queue_get_num_free_words(uint8_t channel);

#endif // SPI_SLAVE_QUEUES_H
