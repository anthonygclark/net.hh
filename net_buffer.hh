#ifndef _NET_BUFFER_HH_
#define _NET_BUFFER_HH_

#include <cstddef>
#include <memory>
#include <type_traits>

namespace net
{
    inline namespace v1
    {
        template<typename T>
            using allocator = std::allocator<T>;

        /**
         * @brief Buffer interface
         */
        class Buffer
        {
        public:
            virtual void * get_data_void() const = 0;
            virtual std::size_t get_size() const = 0;
        };

        /**
         * @brief Represents a data buffer for network communication
         * @tparam T Native type the buffer will hold
         * @tparam align Forced alignment for the buffer. Defaults to alignof(T)
         * @tparam Allocator Memory allocator type
         */
        template<typename T=unsigned char, std::size_t align=alignof(T), typename Allocator=net::allocator<T>>
            class BufferImpl : public Buffer
            {
            private:
                using storage_type = typename std::aligned_storage<sizeof(T), align>::type;

                Allocator m_allocator;
                storage_type * m_data;
                storage_type * m_data_start;
                std::size_t m_num_bytes;
                std::size_t m_num_elements;

            public:
                BufferImpl() :
                    m_data(nullptr),
                    m_data_start(nullptr),
                    m_num_bytes(0),
                    m_num_elements(0)
                { }

                BufferImpl(std::size_t n, T * data) :
                    BufferImpl()
                {
                    m_num_elements = n;
                    m_data = data;
                    m_data_start = m_data;
                    m_num_bytes = sizeof(storage_type) * m_num_elements;
                }

                explicit BufferImpl(std::size_t n, Allocator const & allocator = Allocator()) :
                    BufferImpl()
                {
                    m_allocator = allocator;
                    m_num_elements = n;

                    /* cast is appropriate here since we allocate to the aligned storage type */
                    m_data = reinterpret_cast<storage_type *>(m_allocator.allocate(m_num_elements));
                    m_data_start = m_data;
                    m_num_bytes = sizeof(storage_type) * m_num_elements;

                    /* hmmm we might not need this, but currently it helps my testing with
                     * valgrind
                     */
                    std::memset(m_data, 0, m_num_bytes);
                }

                explicit BufferImpl(BufferImpl const & other) :
                    m_data(other.m_data),
                    m_data_start(other.m_data_start),
                    m_num_bytes(other.m_num_bytes),
                    m_num_elements(other.m_num_elements)
                {
                    other.m_data = nullptr;
                    other.m_data_start = nullptr;
                }

                BufferImpl & operator=(BufferImpl const & other)
                {
                    m_data = other.m_data;
                    m_data_start = other.m_data_start;
                    m_num_bytes = other.m_num_bytes;
                    m_num_elements = other.m_num_elements;

                    return *this;
                }

                ~BufferImpl() {
                    if (m_data != nullptr && m_num_elements > 0) {
                        m_allocator.deallocate(reinterpret_cast<T *>(m_data), m_num_elements);
                        m_data = nullptr;
                    }
                }

                /**
                 * @brief Should only be used to reset the buffer for reuse
                 */
                void reset() {
                    m_data = m_data_start;
                    m_num_bytes = 0;
                    m_num_elements = 0;
                }

                storage_type * get_data() const {
                    return m_data;
                }

                void * get_data_void() const {
                    return reinterpret_cast<void *>(m_data);
                }

                std::size_t get_size() const {
                    return m_num_bytes;
                }
            };


        /**
         * @brief Helper to create a BufferImpl
         * @tparam T See BufferImpl
         * @tparam align See BufferImpl
         * @tparam Allocator See BufferImpl
         * @param n Number of bytes to allocate
         * @param allocator Which allocator to use
         * @return unique_ptr containing BufferImpl
         */
        template<typename T=unsigned char, std::size_t align=alignof(T), typename Allocator=net::allocator<T>>
            std::unique_ptr<BufferImpl<T, align, Allocator>> make_buffer(std::size_t n, Allocator const & allocator = Allocator())
            {
                return std::move(std::make_unique<BufferImpl<T,align,Allocator>>(n, allocator));
            }

    } /* end namespace v1 */
} /* end namespace net */

#endif /* guard */
